package com.prabhix.identity.jwks;

import com.prabhix.identity.config.IdentityProperties;
import com.prabhix.identity.config.TestProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import java.security.KeyPair;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SigningKeyProviderTest {

    private static IdentityProperties properties(String privateKey, List<String> retired) {
        return TestProperties.signing(privateKey, retired);
    }

    private static MockEnvironment environment(String... profiles) {
        MockEnvironment environment = new MockEnvironment();
        environment.setActiveProfiles(profiles);
        return environment;
    }

    @Test
    @DisplayName("derives the public key from the configured private key")
    void derivesPublicKey() {
        KeyPair pair = TestKeys.pair();

        SigningKeyProvider provider = new SigningKeyProvider(
                properties(TestKeys.privatePem(pair), List.of()), environment("prod"));

        // Nothing supplies the public half. If it were configured separately it could be the wrong
        // one, and every product would reject every token with no indication why.
        assertThat(provider.active().publicKey().getModulus())
                .isEqualTo(((java.security.interfaces.RSAPublicKey) pair.getPublic()).getModulus());
    }

    @Test
    @DisplayName("the key id is the key's own thumbprint, so it survives a restart")
    void keyIdIsStable() {
        String pem = TestKeys.privatePem(TestKeys.pair());

        SigningKeyProvider first = new SigningKeyProvider(properties(pem, List.of()), environment("prod"));
        SigningKeyProvider second = new SigningKeyProvider(properties(pem, List.of()), environment("prod"));

        // A restart must not orphan the tokens issued before it: a client that cached the JWKS looks
        // the key up by this id, and a freshly chosen name would not match.
        assertThat(first.active().keyId()).isEqualTo(second.active().keyId());
        assertThat(first.active().keyId()).isNotBlank();
    }

    @Test
    @DisplayName("publishes retired keys alongside the active one")
    void publishesRetiredKeys() {
        KeyPair active = TestKeys.pair();
        KeyPair retired = TestKeys.pair();

        SigningKeyProvider provider = new SigningKeyProvider(
                properties(TestKeys.privatePem(active), List.of(TestKeys.publicPem(retired))),
                environment("prod"));

        assertThat(provider.published()).hasSize(2);
        assertThat(provider.published().get(0).getId()).isEqualTo(provider.active().keyId());
        assertThat(provider.published())
                .allSatisfy(jwk -> assertThat(jwk.getAlgorithm()).isEqualTo("RS256"));
    }

    @Test
    @DisplayName("looks a verification key up by kid and refuses one it does not publish")
    void findsKeyByKeyId() {
        KeyPair active = TestKeys.pair();
        SigningKeyProvider provider = new SigningKeyProvider(
                properties(TestKeys.privatePem(active), List.of()), environment("prod"));

        assertThat(provider.verificationKey(provider.active().keyId())).isPresent();
        assertThat(provider.verificationKey("a-key-we-never-had")).isEmpty();
        assertThat(provider.verificationKey(null)).isEmpty();
    }

    @Test
    @DisplayName("generates a key when none is configured under a local profile")
    void generatesEphemeralKeyLocally() {
        assertThat(new SigningKeyProvider(properties("", List.of()), environment("dev"))
                .active().privateKey()).isNotNull();

        // A bare `mvn spring-boot:run` and an unannotated test both have no active profile.
        assertThat(new SigningKeyProvider(properties(null, List.of()), environment())
                .active().privateKey()).isNotNull();
    }

    @Test
    @DisplayName("refuses to generate a key outside a local profile")
    void refusesEphemeralKeyInProduction() {
        // The failure it prevents is quiet: signing works, verification works, and then a deploy or
        // a second replica invalidates tokens nobody can explain.
        assertThatThrownBy(() -> new SigningKeyProvider(properties("", List.of()), environment("prod")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("IDENTITY_SIGNING_KEY");
    }

    @Test
    @DisplayName("rejects a key that is not a PKCS#8 RSA private key")
    void rejectsMalformedKey() {
        assertThatThrownBy(() -> new SigningKeyProvider(
                properties("-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----",
                        List.of()),
                environment("prod")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("PKCS#8");
    }

    @Test
    @DisplayName("reads a PEM whose newlines arrived as literal backslash-n")
    void readsEscapedPem() {
        String flattened = TestKeys.privatePem(TestKeys.pair()).replace("\n", "\\n");

        // How a PEM usually arrives from a .env file or a container environment variable. Stripping
        // whitespace alone leaves those two characters inside the base64.
        assertThat(new SigningKeyProvider(properties(flattened, List.of()), environment("prod"))
                .active().keyId()).isNotBlank();
    }
}
