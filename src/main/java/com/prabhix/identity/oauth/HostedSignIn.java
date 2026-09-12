package com.prabhix.identity.oauth;

import com.prabhix.identity.config.IdentityProperties;
import com.prabhix.identity.user.IdentityUser;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Signs a browser in once some method has proved who it is, then resumes whatever asked.
 *
 * <p>Form login gets all of this from Spring Security for free. The other methods on the hosted
 * page — magic link, emailed code, SMS, WhatsApp, Google, passkey — verify their proof in a
 * service and then have to do by hand what {@code UsernamePasswordAuthenticationFilter} does after a
 * successful password check. Doing it in one place is what keeps them equivalent: a method that
 * forgot the session-fixation step, or saved no context, would appear to work and be a hole.
 *
 * <p>The principal is the user id and not the address, matching {@link IdentityAuthenticationProvider},
 * because it becomes the {@code sub} claim and an email address is mutable.
 */
@Component
public class HostedSignIn {

    private final SecurityContextRepository contexts = new HttpSessionSecurityContextRepository();

    /**
     * A new session id for the same session.
     *
     * <p>Without this, an attacker who can set a cookie on the browser before sign-in still holds a
     * valid session id afterwards — the session is simply upgraded to authenticated underneath them.
     * Form login applies this by default and these flows would not.
     */
    private final SessionAuthenticationStrategy sessionStrategy = new ChangeSessionIdAuthenticationStrategy();

    private final SavedRequestAwareAuthenticationSuccessHandler success =
            new SavedRequestAwareAuthenticationSuccessHandler();

    public HostedSignIn(IdentityProperties properties) {
        // Where to go when nothing was saved. A magic link opened on a phone, while the flow was
        // started on a laptop, has no authorization request in this session to resume — so it lands
        // in the console rather than on a dead end.
        success.setDefaultTargetUrl(properties.urls().console());
    }

    /**
     * @param factor which proof was just given, as a {@code FactorGrantedAuthority} constant. It ends
     *     up as the ID token's {@code auth_time}, so it is required rather than defaulted: a wrong
     *     factor is a false statement to every product that reads the claim.
     */
    public void completeAndRedirect(IdentityUser user,
                                   String factor,
                                   HttpServletRequest request,
                                   HttpServletResponse response) throws IOException, ServletException {
        UsernamePasswordAuthenticationToken authentication = UsernamePasswordAuthenticationToken.authenticated(
                user.getId().toString(),
                null,
                SignInAuthorities.forFactor(factor));
        authentication.setDetails(user.getEmail());

        sessionStrategy.onAuthentication(authentication, request, response);

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        // Held in the session, not just the thread: the pending /oauth2/authorize arrives as a
        // separate request and reads it from there.
        contexts.saveContext(context, request, response);

        success.onAuthenticationSuccess(request, response, authentication);
    }
}
