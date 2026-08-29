package com.prabhix.identity.token;

import com.prabhix.identity.config.IdentityProperties;
import com.prabhix.identity.jwks.SigningKeyProvider;
import com.prabhix.identity.jwks.TestKeys;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TokenServiceTest {

    private static final String ISSUER = "https://id.prabhixtechnologies.com";

    private static IdentityProperties properties(String privateKey, List<String> retired) {
        return new IdentityProperties(
                ISSUER,
                new IdentityProperties.Token(Duration.ofMinutes(15)),
                new IdentityProperties.Signing(privateKey, retired));
    }

    private static IdentityClaims claims() {
        return new IdentityClaims(
                UUID.randomUUID(),
                "owner@prabhixtechnologies.com",
                true,
                "Demo Owner",
                UUID.randomUUID(),
                List.of("pwd"));
    }

    private static SigningKeyProvider provider(IdentityProperties properties) {
        return new SigningKeyProvider(properties, new MockEnvironment());
    }

    @Test
    @DisplayName("a token it issues verifies, with every claim intact")
    void roundTrip() {
        IdentityProperties properties = properties(TestKeys.privatePem(TestKeys.pair()), List.of());
        TokenService service = new TokenService(provider(properties), properties);
        IdentityClaims original = claims();

        TokenService.IssuedToken issued = service.issue(original);

        assertThat(issued.expiresAt()).isAfter(Instant.now().plus(Duration.ofMinutes(14)));
        assertThat(service.verify(issued.token())).isEqualTo(original);
    }

    @Test
    @DisplayName("signs RS256 and names the key in the header")
    void signsRs256WithKeyId() {
        IdentityProperties properties = properties(TestKeys.privatePem(TestKeys.pair()), List.of());
        SigningKeyProvider keys = provider(properties);
        TokenService service = new TokenService(keys, properties);

        String token = service.issue(claims()).token();

        // The header is what a product reads before it has any key, so it decides whether offline
        // verification is possible at all.
        var header = Jwts.parser().verifyWith(keys.active().publicKey()).build()
                .parseSignedClaims(token).getHeader();
        assertThat(header.getAlgorithm()).isEqualTo("RS256");
        assertThat(header.getKeyId()).isEqualTo(keys.active().keyId());
    }

    @Test
    @DisplayName("carries no product permissions")
    void carriesNoPermissions() {
        IdentityProperties properties = properties(TestKeys.privatePem(TestKeys.pair()), List.of());
        SigningKeyProvider keys = provider(properties);
        TokenService service = new TokenService(keys, properties);

        var payload = Jwts.parser().verifyWith(keys.active().publicKey()).build()
                .parseSignedClaims(service.issue(claims()).token()).getPayload();

        // The platform's own token has perms and org, MobiStack's has its own set and shop. Both
        // stay behind: this service must not need a release to change a repair-shop permission.
        assertThat(payload).doesNotContainKeys("perms", "permissions", "org", "shop", "roles");
    }

    @Test
    @DisplayName("a token signed by a key we no longer publish is rejected")
    void rejectsUnknownKey() {
        KeyPair stranger = TestKeys.pair();
        IdentityProperties properties = properties(TestKeys.privatePem(TestKeys.pair()), List.of());
        TokenService service = new TokenService(provider(properties), properties);

        String forged = Jwts.builder()
                .header().keyId("some-other-key").and()
                .issuer(ISSUER)
                .subject(UUID.randomUUID().toString())
                .claim("sid", UUID.randomUUID().toString())
                .expiration(Date.from(Instant.now().plus(Duration.ofMinutes(5))))
                .signWith(stranger.getPrivate(), Jwts.SIG.RS256)
                .compact();

        assertThatThrownBy(() -> service.verify(forged))
                .isInstanceOf(SignatureException.class);
    }

    @Test
    @DisplayName("a token from a key that has since been retired still verifies")
    void acceptsRetiredKeyDuringRotation() {
        KeyPair old = TestKeys.pair();
        IdentityProperties before = properties(TestKeys.privatePem(old), List.of());
        String issuedBeforeRotation = new TokenService(provider(before), before)
                .issue(claims()).token();

        IdentityProperties after = properties(
                TestKeys.privatePem(TestKeys.pair()), List.of(TestKeys.publicPem(old)));
        TokenService rotated = new TokenService(provider(after), after);

        // Access tokens live 15 minutes. Rotating without keeping the old public key means every
        // token issued in the previous 15 minutes stops verifying the moment the new one takes over.
        assertThat(rotated.verify(issuedBeforeRotation)).isNotNull();
    }

    @Test
    @DisplayName("a token issued for a different issuer is rejected")
    void rejectsForeignIssuer() {
        KeyPair pair = TestKeys.pair();
        IdentityProperties staging = new IdentityProperties(
                "https://id.staging.prabhixtechnologies.com",
                new IdentityProperties.Token(Duration.ofMinutes(15)),
                new IdentityProperties.Signing(TestKeys.privatePem(pair), List.of()));
        String stagingToken = new TokenService(provider(staging), staging).issue(claims()).token();

        IdentityProperties production = properties(TestKeys.privatePem(pair), List.of());
        TokenService service = new TokenService(provider(production), production);

        // Same key, different deployment. Without the issuer check a staging token would be a
        // production token, which is the failure mode of sharing a key across environments.
        assertThatThrownBy(() -> service.verify(stagingToken))
                .isInstanceOf(io.jsonwebtoken.IncorrectClaimException.class);
    }

    @Test
    @DisplayName("an expired token is rejected")
    void rejectsExpiredToken() {
        IdentityProperties expired = new IdentityProperties(
                ISSUER,
                new IdentityProperties.Token(Duration.ofSeconds(-60)),
                new IdentityProperties.Signing(TestKeys.privatePem(TestKeys.pair()), List.of()));
        TokenService service = new TokenService(provider(expired), expired);

        String token = service.issue(claims()).token();

        assertThatThrownBy(() -> service.verify(token))
                .isInstanceOf(io.jsonwebtoken.ExpiredJwtException.class);
    }
}
