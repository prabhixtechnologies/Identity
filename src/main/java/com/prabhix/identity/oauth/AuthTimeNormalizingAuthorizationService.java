package com.prabhix.identity.oauth;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;

import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Makes a stored {@code auth_time} readable by the refresh-token grant.
 *
 * <p>Spring's {@code JwtGenerator} copies {@code auth_time} off the previous ID token and casts it to
 * {@link Date}. This service used to store the epoch second instead, which is a legal JWT number and
 * a {@code ClassCastException} the moment a phone refreshes. That exception leaves
 * {@code /oauth2/token} answering 500, the access token expires, and every catalog call stops before
 * a fitment group is known — the app then draws "0 brands" for a catalog it never loaded.
 *
 * <p>Rows already written with a number, and any claim Jackson restores as an {@link Instant}, are
 * rewritten on read. A session issued before the claim type was corrected refreshes without a new
 * sign-in.
 */
final class AuthTimeNormalizingAuthorizationService implements OAuth2AuthorizationService {

    private final OAuth2AuthorizationService delegate;

    AuthTimeNormalizingAuthorizationService(OAuth2AuthorizationService delegate) {
        this.delegate = delegate;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        delegate.save(authorization);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        delegate.remove(authorization);
    }

    @Override
    @Nullable
    public OAuth2Authorization findById(String id) {
        return normalize(delegate.findById(id));
    }

    @Override
    @Nullable
    public OAuth2Authorization findByToken(String token, @Nullable OAuth2TokenType tokenType) {
        return normalize(delegate.findByToken(token, tokenType));
    }

    @Nullable
    private static OAuth2Authorization normalize(@Nullable OAuth2Authorization authorization) {
        if (authorization == null) {
            return null;
        }
        OAuth2Authorization.Token<OidcIdToken> token = authorization.getToken(OidcIdToken.class);
        if (token == null) {
            return authorization;
        }
        Object authTime = token.getToken().getClaim(IdTokenClaimNames.AUTH_TIME);
        if (authTime instanceof Date || authTime == null) {
            return authorization;
        }
        Date asDate = asDate(authTime);
        if (asDate == null) {
            return authorization;
        }
        Map<String, Object> claims = new LinkedHashMap<>(token.getToken().getClaims());
        claims.put(IdTokenClaimNames.AUTH_TIME, asDate);
        OidcIdToken idToken = token.getToken();
        OidcIdToken fixed = new OidcIdToken(
                idToken.getTokenValue(), idToken.getIssuedAt(), idToken.getExpiresAt(), claims);
        return OAuth2Authorization.from(authorization)
                .token(fixed, metadata -> {
                    metadata.putAll(token.getMetadata());
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims);
                })
                .build();
    }

    @Nullable
    private static Date asDate(Object authTime) {
        if (authTime instanceof Date date) {
            return date;
        }
        if (authTime instanceof Instant instant) {
            return Date.from(instant);
        }
        if (authTime instanceof Number number) {
            return Date.from(Instant.ofEpochSecond(number.longValue()));
        }
        return null;
    }
}
