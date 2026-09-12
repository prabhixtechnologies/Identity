package com.prabhix.identity.oauth;

import org.springframework.lang.Nullable;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.time.Instant;
import java.util.Base64;

/**
 * Issues refresh tokens to first-party public clients (mobile apps).
 *
 * <p>Spring's {@code OAuth2RefreshTokenGenerator} deliberately returns null for
 * {@code authorization_code} when the client authenticated with
 * {@link org.springframework.security.oauth2.core.ClientAuthenticationMethod#NONE}. That is the
 * right default for anonymous SPAs on the open web. Our Android clients are also public (they cannot
 * hold a client secret), but they need a refresh token — access tokens last thirty minutes and a
 * phone that re-prompts at every expiry is not a product people keep.
 *
 * <p>Rotation stays on ({@code reuseRefreshTokens(false)} in the seeder). A stolen refresh token is
 * still detectable; this only removes the blanket refusal to mint one.
 */
final class PublicClientRefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {

    private final StringKeyGenerator refreshTokenGenerator = new Base64StringKeyGenerator(
            Base64.getUrlEncoder().withoutPadding(), 96);

    @Override
    @Nullable
    public OAuth2RefreshToken generate(OAuth2TokenContext context) {
        if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
            return null;
        }
        if (!context.getRegisteredClient().getAuthorizationGrantTypes()
                .contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            return null;
        }

        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(
                context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive());
        return new OAuth2RefreshToken(this.refreshTokenGenerator.generateKey(), issuedAt, expiresAt);
    }
}
