package com.prabhix.identity.client;

import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IdentityTokenVerifierTest {

    private static final String ISSUER = "https://api.prabhixtechnologies.com";
    private static KeyPair keyPair;
    private static KeyPair otherPair;

    private final IdentityClientProperties config = new IdentityClientProperties(
            ISSUER, null, null, null, Duration.ZERO, null, null, null);

    @BeforeAll
    static void keys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
        otherPair = generator.generateKeyPair();
    }

    private IdentityTokenVerifier verifier(Map<String, PublicKey> published) {
        IdentityKeySource source = new IdentityKeySource(config, null) {
            @Override
            public Optional<PublicKey> verificationKey(String keyId) {
                return Optional.ofNullable(published.get(keyId));
            }
        };
        return new IdentityTokenVerifier(config, source);
    }

    private String token(KeyPair pair, String kid, Instant exp, UUID subject) {
        return Jwts.builder()
                .header().keyId(kid).and()
                .issuer(ISSUER)
                .subject(subject.toString())
                .id("jti-1")
                .issuedAt(Date.from(Instant.now().minusSeconds(5)))
                .expiration(Date.from(exp))
                .claim("email", "ada@example.com")
                .claim("email_verified", true)
                .claim("name", "Ada")
                .claim("sid", "6d1e4c40-2f3f-4a3a-9d3d-7a1b2c3d4e5f")
                .claim("amr", List.of("pwd", "otp"))
                .signWith(pair.getPrivate(), Jwts.SIG.RS256)
                .compact();
    }

    @Test
    void readsIdentityClaimsFromAValidToken() {
        UUID subject = UUID.randomUUID();
        String jwt = token(keyPair, "k1", Instant.now().plusSeconds(60), subject);

        IdentityToken parsed = verifier(Map.of("k1", keyPair.getPublic())).verify(jwt);

        assertThat(parsed.subject()).isEqualTo(subject);
        assertThat(parsed.email()).isEqualTo("ada@example.com");
        assertThat(parsed.emailVerified()).isTrue();
        assertThat(parsed.name()).isEqualTo("Ada");
        assertThat(parsed.sessionId()).isEqualTo(UUID.fromString("6d1e4c40-2f3f-4a3a-9d3d-7a1b2c3d4e5f"));
        assertThat(parsed.tokenId()).isEqualTo("jti-1");
        assertThat(parsed.authenticationMethods()).containsExactly("pwd", "otp");
        assertThat(parsed.issuedAt()).isNotNull();
    }

    @Test
    void refusesAnExpiredTokenAsExpiredNotInvalid() {
        String jwt = token(keyPair, "k1", Instant.now().minusSeconds(60), UUID.randomUUID());

        assertThatThrownBy(() -> verifier(Map.of("k1", keyPair.getPublic())).verify(jwt))
                .isInstanceOf(IdentityTokenException.class)
                .extracting(ex -> ((IdentityTokenException) ex).reason())
                .isEqualTo(IdentityTokenException.Reason.EXPIRED);
    }

    @Test
    void refusesAKeyIdentityDoesNotPublish() {
        String jwt = token(otherPair, "rogue", Instant.now().plusSeconds(60), UUID.randomUUID());

        assertThatThrownBy(() -> verifier(Map.of("k1", keyPair.getPublic())).verify(jwt))
                .isInstanceOf(IdentityTokenException.class)
                .extracting(ex -> ((IdentityTokenException) ex).reason())
                .isEqualTo(IdentityTokenException.Reason.INVALID);
    }

    @Test
    void refusesAValidKeyIdWithTheWrongPrivateKey() {
        String jwt = token(otherPair, "k1", Instant.now().plusSeconds(60), UUID.randomUUID());

        assertThatThrownBy(() -> verifier(Map.of("k1", keyPair.getPublic())).verify(jwt))
                .isInstanceOf(IdentityTokenException.class);
    }

    @Test
    void refusesHmacTokensEvenWhenTheyNameAPublishedKey() {
        SecretKey secret = Jwts.SIG.HS256.key().build();
        String jwt = Jwts.builder()
                .header().keyId("k1").and()
                .issuer(ISSUER)
                .subject(UUID.randomUUID().toString())
                .expiration(Date.from(Instant.now().plusSeconds(60)))
                .signWith(secret, Jwts.SIG.HS256)
                .compact();

        assertThatThrownBy(() -> verifier(Map.of("k1", keyPair.getPublic())).verify(jwt))
                .isInstanceOf(IdentityTokenException.class)
                .extracting(ex -> ((IdentityTokenException) ex).reason())
                .isEqualTo(IdentityTokenException.Reason.INVALID);
    }

    @Test
    void refusesAnotherIssuerSignedWithTheRightKey() {
        String jwt = Jwts.builder()
                .header().keyId("k1").and()
                .issuer("https://evil.example")
                .subject(UUID.randomUUID().toString())
                .expiration(Date.from(Instant.now().plusSeconds(60)))
                .signWith(keyPair.getPrivate(), Jwts.SIG.RS256)
                .compact();

        assertThatThrownBy(() -> verifier(Map.of("k1", keyPair.getPublic())).verify(jwt))
                .isInstanceOf(IdentityTokenException.class)
                .extracting(ex -> ((IdentityTokenException) ex).reason())
                .isEqualTo(IdentityTokenException.Reason.INVALID);
    }

    @Test
    void refusesEverythingWhenNoIssuerIsConfigured() {
        IdentityClientProperties disabled = new IdentityClientProperties(
                "", null, null, null, null, null, null, null);
        IdentityTokenVerifier verifier = new IdentityTokenVerifier(disabled, new IdentityKeySource(disabled, null));

        assertThatThrownBy(() -> verifier.verify(token(keyPair, "k1", Instant.now().plusSeconds(60), UUID.randomUUID())))
                .isInstanceOf(IdentityTokenException.class)
                .extracting(ex -> ((IdentityTokenException) ex).reason())
                .isEqualTo(IdentityTokenException.Reason.UNTRUSTED);
    }

    @Test
    void propertiesDeriveTheJwksUriFromTheIssuer() {
        assertThat(config.effectiveJwksUri()).isEqualTo(ISSUER + "/.well-known/jwks.json");
        assertThat(config.enabled()).isTrue();
        assertThat(config.canCallInternal()).isFalse();

        IdentityClientProperties full = new IdentityClientProperties(
                ISSUER + "/", "http://identity:8081/.well-known/jwks.json", null, null, null,
                "http://identity:8081/", "secret", null);
        assertThat(full.effectiveJwksUri()).isEqualTo("http://identity:8081/.well-known/jwks.json");
        assertThat(full.internalBaseUrl()).isEqualTo("http://identity:8081");
        assertThat(full.canCallInternal()).isTrue();
    }
}
