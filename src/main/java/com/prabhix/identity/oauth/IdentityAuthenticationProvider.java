package com.prabhix.identity.oauth;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.event.AuthEventRecorder;
import com.prabhix.identity.event.AuthEventType;
import com.prabhix.identity.user.CredentialService;
import com.prabhix.identity.user.IdentityUser;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.stereotype.Component;

import static com.prabhix.identity.event.AuthEventRecorder.details;

/**
 * Password authentication for the hosted login page.
 *
 * <p>Delegates to {@link CredentialService} rather than using Spring's
 * {@code DaoAuthenticationProvider}, so the browser flow and the API flow enforce exactly the same
 * rules. A {@code UserDetailsService} would compare the hash and nothing else — losing the failed
 * attempt counter, the lockout window, and the refusal to admit a suspended account. Two code paths
 * to the same door, with only one of them locked, is how brute-force protection ends up being
 * technically present and practically absent.
 *
 * <p>The resulting principal name is the user id, because that becomes the {@code sub} claim, and an
 * email address is a poor subject: it is mutable, and anything keyed by it breaks when somebody
 * changes theirs.
 */
@Component
@RequiredArgsConstructor
public class IdentityAuthenticationProvider implements AuthenticationProvider {

    private final CredentialService credentials;
    private final AuthEventRecorder events;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String email = String.valueOf(authentication.getPrincipal());
        String password = String.valueOf(authentication.getCredentials());

        IdentityUser user;
        try {
            user = credentials.authenticate(email, password);
        } catch (ApiException ex) {
            // Deliberately reduced to two outcomes. The service distinguishes an unknown address from
            // a wrong password, which is right for its own callers and wrong to show on a login form:
            // it turns the page into an oracle for which addresses have accounts.
            throw switch (ex.getCode()) {
                case ACCOUNT_LOCKED -> new LockedException(ex.getMessage());
                default -> new BadCredentialsException("Those details do not match an account");
            };
        }

        // Failures are recorded inside CredentialService, where the reason is known. Success is
        // recorded here because the service does not know which surface asked.
        events.success(AuthEventType.LOGIN_SUCCEEDED, user.getId(), user.getEmail(),
                details("method", "pwd", "surface", "hosted"));

        var authenticated = UsernamePasswordAuthenticationToken.authenticated(
                user.getId().toString(),
                null,
                SignInAuthorities.forFactor(FactorGrantedAuthority.PASSWORD_AUTHORITY));
        authenticated.setDetails(user.getEmail());
        return authenticated;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
