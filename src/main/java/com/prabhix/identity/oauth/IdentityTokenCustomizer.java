package com.prabhix.identity.oauth;

import com.prabhix.identity.user.IdentityUser;
import com.prabhix.identity.user.IdentityUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Puts the same claims on an authorization-code token that the direct sign-in endpoints already put
 * on theirs.
 *
 * <p>Without this, a product would see two shapes of token depending on which flow minted it, and
 * would have to call {@code /userinfo} for a name it used to read locally. The set matches
 * {@code TokenService}: {@code email}, {@code email_verified}, {@code name}, {@code sid} and
 * {@code amr} — except that {@code sid} goes only on the access token, because on an id_token the
 * claim belongs to the authorization server and writing over it breaks sign-out.
 *
 * <p>Still nothing about authority. No organization, no permissions, no roles — a product resolves
 * those against its own database, which is what stops a token from being a standing grant that outlives
 * the access it describes.
 */
@Component
@RequiredArgsConstructor
public class IdentityTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private final IdentityUserRepository users;

    @Override
    public void customize(JwtEncodingContext context) {
        boolean accessToken = OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType());
        boolean idToken = "id_token".equals(context.getTokenType().getValue());
        if (!accessToken && !idToken) {
            return;
        }

        // The authorization's principal name is the user id, set by IdentityAuthenticationProvider, so
        // sub is a UUID rather than an email address. An email address makes a poor subject: it is
        // mutable, and every row keyed by it breaks when somebody changes theirs.
        UUID userId;
        try {
            userId = UUID.fromString(context.getPrincipal().getName());
        } catch (IllegalArgumentException ex) {
            return;
        }

        users.findByIdAndDeletedAtIsNull(userId).ifPresent(user -> {
            context.getClaims().claim("email", user.getEmail());
            context.getClaims().claim("email_verified", user.isEmailVerified());
            context.getClaims().claim("name", displayName(user));
        });

        // Only on the access token, and that restriction is load-bearing.
        //
        // On an id_token, sid already means something specific: the authorization server's own session
        // with the browser, which it writes from the session registry and reads back to validate an
        // `id_token_hint` at /connect/logout. Overwriting it with the authorization id guaranteed a
        // mismatch, so RP-initiated logout answered 400 to every request that ever reached it — and a
        // sign-out that cannot end the session at the provider is not a sign-out at all: the next
        // /authorize finds the session still live and signs the person straight back in, which on a
        // shared machine is somebody else's account left open.
        //
        // The access token has no such claim of its own, and products key their revocation checks on
        // this one, so it keeps the authorization id. The two therefore differ, deliberately: they
        // answer different questions, one about the provider's session and one about this grant.
        if (accessToken) {
            context.getClaims().claim("sid", context.getAuthorization() == null
                    ? context.getPrincipal().getName()
                    : context.getAuthorization().getId());
        }

        // What was actually proved, rather than a constant. This was hardcoded to "pwd", which told
        // every product that a password had been typed even when the person had clicked a link in
        // their mail or come through Google — and amr exists precisely so a product can insist on a
        // password before showing something sensitive. A claim that always says the same thing cannot
        // support that decision and quietly answers it wrongly.
        //
        // Absent when the factor does not map onto a registered amr value, which is the honest answer:
        // RFC 8176 has no value for "arrived through an external provider", and inventing one that
        // relying parties will compare against is worse than saying nothing.
        authenticationMethods(context).ifPresent(amr -> context.getClaims().claim("amr", amr));
    }

    /**
     * Reads the factor Spring Security stamped on the authentication at sign-in.
     *
     * <p>{@code SignInAuthorities} records it for every method the hosted page offers, so this is the
     * one place that knows which of them happened. Spring has no OTP-specific factor — a mailed code
     * and a mailed link are both one-time tokens — so both report {@code otp}, which is what RFC 8176
     * means by the value and true of either.
     */
    private Optional<List<String>> authenticationMethods(JwtEncodingContext context) {
        return context.getPrincipal().getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .map(AMR_BY_FACTOR::get)
                .filter(Objects::nonNull)
                .findFirst()
                .map(List::of);
    }

    /**
     * Spring's factor authorities to the {@code amr} values of RFC 8176.
     *
     * <p>A map rather than a switch because these are fields on another class, and a case label needs
     * a compile-time constant — which is a property of how Spring happens to initialize them today
     * rather than anything it promises.
     *
     * <p>Deliberately partial. {@code AUTHORIZATION_CODE} is what an external provider leaves behind,
     * and the registry has no value meaning "somebody else vouched for them", so it maps to nothing
     * and the claim is left off.
     */
    private static final Map<String, String> AMR_BY_FACTOR = Map.of(
            FactorGrantedAuthority.PASSWORD_AUTHORITY, "pwd",
            FactorGrantedAuthority.OTT_AUTHORITY, "otp",
            FactorGrantedAuthority.WEBAUTHN_AUTHORITY, "swk",
            FactorGrantedAuthority.X509_AUTHORITY, "swk");

    private String displayName(IdentityUser user) {
        if (user.getDisplayName() != null && !user.getDisplayName().isBlank()) {
            return user.getDisplayName();
        }
        return user.getFullName();
    }
}
