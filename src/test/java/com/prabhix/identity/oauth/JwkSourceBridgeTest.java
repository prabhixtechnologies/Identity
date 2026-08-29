package com.prabhix.identity.oauth;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.prabhix.identity.config.IdentityProperties;
import com.prabhix.identity.config.TestProperties;
import com.prabhix.identity.jwks.SigningKeyProvider;
import com.prabhix.identity.jwks.TestKeys;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The authorization server signs with the key this service already publishes.
 *
 * <p>Worth a test because the failure is silent and total: Spring Authorization Server will happily
 * generate its own key pair if one is not supplied, and then every token minted through the
 * authorization code flow is signed by a key absent from the JWKS — so it verifies nowhere, while
 * tokens from the direct sign-in endpoints keep working. Half the logins break and the other half do
 * not, which is a bad afternoon.
 *
 * <p>The endpoints themselves are no longer asserted here. They are the framework's now, and
 * re-testing Spring's discovery document only proves Spring works.
 */
class JwkSourceBridgeTest {

    private final AuthorizationServerConfig config = new AuthorizationServerConfig();

    @Test
    @DisplayName("the signing key id matches the one published in the JWKS")
    void keyIdMatchesTheProvider() throws Exception {
        SigningKeyProvider keys = provider(TestKeys.privatePem(TestKeys.pair()), List.of());

        List<JWK> published = select(config.jwkSource(keys));

        // Both libraries compute an RFC 7638 thumbprint, so the id has to come out identical. If it
        // did not, a token issued before this change would name a kid nothing publishes.
        assertThat(published).hasSize(1);
        assertThat(published.get(0).getKeyID()).isEqualTo(keys.active().keyId());
    }

    @Test
    @DisplayName("the active key can sign and a retired key cannot")
    void onlyTheActiveKeyCarriesAPrivateHalf() throws Exception {
        SigningKeyProvider keys = provider(
                TestKeys.privatePem(TestKeys.pair()), List.of(TestKeys.publicPem(TestKeys.pair())));

        List<JWK> published = select(config.jwkSource(keys));

        assertThat(published).hasSize(2);

        JWK active = published.stream()
                .filter(jwk -> jwk.getKeyID().equals(keys.active().keyId()))
                .findFirst()
                .orElseThrow();
        assertThat(active.isPrivate()).isTrue();

        // A retired key is for verifying tokens issued before the rotation and must not be able to
        // sign a new one. Publishing it with a private half would make retiring a key meaningless.
        JWK retired = published.stream()
                .filter(jwk -> !jwk.getKeyID().equals(keys.active().keyId()))
                .findFirst()
                .orElseThrow();
        assertThat(retired.isPrivate()).isFalse();
    }

    @Test
    @DisplayName("the public view of the key set never contains the private exponent")
    void publicViewLeaksNothing() throws Exception {
        SigningKeyProvider keys = provider(TestKeys.privatePem(TestKeys.pair()), List.of());

        JWK active = select(config.jwkSource(keys)).get(0);
        String publicJson = active.toPublicJWK().toJSONString();

        assertThat(publicJson).contains("\"kty\":\"RSA\"");
        // d is the private exponent, p and q its factors. This is what the JWKS endpoint serves.
        assertThat(publicJson).doesNotContain("\"d\"").doesNotContain("\"p\"").doesNotContain("\"q\"");
    }

    private SigningKeyProvider provider(String privateKey, List<String> retired) {
        IdentityProperties properties = TestProperties.signing(privateKey, retired);
        return new SigningKeyProvider(properties, new MockEnvironment());
    }

    private List<JWK> select(JWKSource<SecurityContext> source) throws Exception {
        return source.get(new JWKSelector(new JWKMatcher.Builder().build()), null);
    }
}
