package com.prabhix.identity.oauth;

import com.prabhix.identity.user.IdentityUser;
import com.prabhix.identity.user.IdentityUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.UUID;

/**
 * Puts the same claims on an authorization-code token that the direct sign-in endpoints already put
 * on theirs.
 *
 * <p>Without this, a product would see two shapes of token depending on which flow minted it, and
 * would have to call {@code /userinfo} for a name it used to read locally. The set is deliberately
 * identical to {@code TokenService}: {@code email}, {@code email_verified}, {@code name}, {@code sid}
 * and {@code amr}.
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

        // The browser session this authorization belongs to. Products key their revocation checks on
        // it, so signing out of one has to be recognisable in the others.
        context.getClaims().claim("sid", context.getAuthorization() == null
                ? context.getPrincipal().getName()
                : context.getAuthorization().getId());
        context.getClaims().claim("amr", List.of("pwd"));
    }

    private String displayName(IdentityUser user) {
        if (user.getDisplayName() != null && !user.getDisplayName().isBlank()) {
            return user.getDisplayName();
        }
        return user.getFullName();
    }
}
