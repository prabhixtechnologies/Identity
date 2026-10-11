package com.prabhix.identity.oauth;

import org.junit.jupiter.api.Test;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.time.Instant;
import java.util.Date;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The refresh grant casts {@code auth_time} to {@link Date}. A number or an {@link Instant} left in
 * the saved ID token is a 500 from {@code /oauth2/token}, which is what leaves the phone with no
 * fitment group.
 */
class AuthTimeNormalizingAuthorizationServiceTest {

    private static final Instant ISSUED_AT = Instant.parse("2026-10-11T12:00:00Z");

    @Test
    void aNumericAuthTimeIsADateWhenTheAuthorizationIsRead() {
        long epochSecond = ISSUED_AT.getEpochSecond();
        OAuth2Authorization read = read(Map.of(
                "sub", "user",
                IdTokenClaimNames.AUTH_TIME, epochSecond));

        Object authTime = idToken(read).getClaim(IdTokenClaimNames.AUTH_TIME);
        assertThat(authTime).isEqualTo(Date.from(ISSUED_AT));
    }

    @Test
    void anInstantAuthTimeIsADateWhenTheAuthorizationIsRead() {
        OAuth2Authorization read = read(Map.of(
                "sub", "user",
                IdTokenClaimNames.AUTH_TIME, ISSUED_AT));

        Object authTime = idToken(read).getClaim(IdTokenClaimNames.AUTH_TIME);
        assertThat(authTime).isEqualTo(Date.from(ISSUED_AT));
    }

    @Test
    void aDateAuthTimeIsLeftAlone() {
        Date authTime = Date.from(ISSUED_AT);
        OAuth2Authorization stored = authorization(Map.of(
                "sub", "user",
                IdTokenClaimNames.AUTH_TIME, authTime));
        OAuth2Authorization read = new AuthTimeNormalizingAuthorizationService(new Fixed(stored))
                .findByToken("refresh-token", OAuth2TokenType.REFRESH_TOKEN);

        assertThat(read).isSameAs(stored);
    }

    private static OAuth2Authorization read(Map<String, Object> claims) {
        return new AuthTimeNormalizingAuthorizationService(new Fixed(authorization(claims)))
                .findByToken("refresh-token", OAuth2TokenType.REFRESH_TOKEN);
    }

    private static OidcIdToken idToken(OAuth2Authorization authorization) {
        return authorization.getToken(OidcIdToken.class).getToken();
    }

    private static OAuth2Authorization authorization(Map<String, Object> claims) {
        RegisteredClient client = RegisteredClient.withId("client")
                .clientId("prabhix-mobistack-android")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("mobistack:/oauth2redirect")
                .scope("openid")
                .build();
        OidcIdToken idToken = new OidcIdToken(
                "id-token", ISSUED_AT, ISSUED_AT.plusSeconds(900), claims);
        return OAuth2Authorization.withRegisteredClient(client)
                .principalName("user")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(client.getScopes())
                .token(idToken, metadata -> metadata.put(
                        OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idToken.getClaims()))
                .attribute("state", "kept")
                .build();
    }

    private static final class Fixed implements OAuth2AuthorizationService {

        private final OAuth2Authorization authorization;

        private Fixed(OAuth2Authorization authorization) {
            this.authorization = authorization;
        }

        @Override
        public void save(OAuth2Authorization authorization) {
        }

        @Override
        public void remove(OAuth2Authorization authorization) {
        }

        @Override
        public OAuth2Authorization findById(String id) {
            return authorization;
        }

        @Override
        @Nullable
        public OAuth2Authorization findByToken(String token, @Nullable OAuth2TokenType tokenType) {
            return authorization;
        }
    }
}
