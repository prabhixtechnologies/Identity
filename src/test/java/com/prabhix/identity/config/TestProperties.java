package com.prabhix.identity.config;

import com.prabhix.identity.config.IdentityProperties.Challenge;
import com.prabhix.identity.config.IdentityProperties.Lockout;
import com.prabhix.identity.config.IdentityProperties.Password;
import com.prabhix.identity.config.IdentityProperties.SessionCookie;
import com.prabhix.identity.config.IdentityProperties.Signing;
import com.prabhix.identity.config.IdentityProperties.Sso;
import com.prabhix.identity.config.IdentityProperties.Token;
import com.prabhix.identity.config.IdentityProperties.Urls;

import java.time.Duration;
import java.util.List;

/**
 * Builds {@link IdentityProperties} for unit tests.
 *
 * <p>Exists so that adding a configuration group does not mean editing a constructor call in every
 * test that only cares about signing keys. Defaults mirror {@code application.yml}, so a test that
 * does not name a value gets production behaviour rather than a convenient fiction.
 */
public final class TestProperties {

    public static final String ISSUER = "https://id.prabhixtechnologies.com";

    private TestProperties() {
    }

    public static IdentityProperties signing(String privateKey, List<String> retiredPublicKeys) {
        return forIssuer(ISSUER, privateKey, retiredPublicKeys);
    }

    public static IdentityProperties forIssuer(String issuer,
                                               String privateKey,
                                               List<String> retiredPublicKeys) {
        return new IdentityProperties(
                issuer,
                new Token(Duration.ofMinutes(15), Duration.ofDays(30)),
                new Signing(privateKey, retiredPublicKeys),
                new Password(10, 12),
                new Lockout(5, Duration.ofMinutes(15)),
                new Challenge(6, Duration.ofMinutes(10), 5),
                new SessionCookie("pbx_session", "", true, "Lax"),
                new Urls("https://app.prabhixtechnologies.com", "https://admin.prabhixtechnologies.com"),
                new Sso(""),
                // No SMS provider, so the phone flows refuse. Any test that needs them stubs
                // SmsSender directly rather than reaching a real one from a unit test.
                new IdentityProperties.Sms("", "", "", ""),
                // No OAuth clients. Every test here exercises the direct sign-in path or key
                // handling; the authorization code flow needs a booted server, not a unit test.
                List.of(),
                "test-service-token");
    }

    /** For the expiry test, which needs a token that is already past its expiration. */
    public static IdentityProperties withAccessTtl(String privateKey, Duration accessTokenTtl) {
        IdentityProperties base = signing(privateKey, List.of());
        return new IdentityProperties(
                base.issuer(),
                new Token(accessTokenTtl, base.token().refreshTokenTtl()),
                base.signing(),
                base.password(),
                base.lockout(),
                base.challenge(),
                base.sessionCookie(),
                base.urls(),
                base.sso(),
                base.sms(),
                base.clients(),
                base.serviceToken());
    }
}
