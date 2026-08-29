package com.prabhix.identity.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;
import java.util.List;

/**
 * @param serviceToken shared secret a product presents to read user records from {@code /internal}.
 *     A shared secret rather than mTLS or a signed assertion because there are three consumers on
 *     one host and the endpoint is not routed publicly; blank disables the endpoint entirely, which
 *     is the correct default for a deployment that has not been given one.
 */
@ConfigurationProperties(prefix = "prabhix.identity")
public record IdentityProperties(
        String issuer,
        Token token,
        Signing signing,
        Password password,
        Lockout lockout,
        Challenge challenge,
        SessionCookie sessionCookie,
        Urls urls,
        Sso sso,
        String serviceToken) {

    /**
     * @param accessTokenTtl matches the platform's 15 minutes. Short because access tokens carry no
     *     revocation check of their own — a signature is valid until it expires, and the products
     *     verifying it offline cannot ask whether the session still exists.
     * @param refreshTokenTtl also how long a signed-in browser stays signed in, since the session
     *     cookie shares this knob
     */
    public record Token(
            @DefaultValue("PT15M") Duration accessTokenTtl,
            @DefaultValue("P30D") Duration refreshTokenTtl) {
    }

    /**
     * @param privateKey PKCS#8 PEM of the active signing key. Blank generates an ephemeral key,
     *     which {@code SigningKeyProvider} permits only under a local profile.
     * @param retiredPublicKeys X.509 PEM public keys that no longer sign but are still published in
     *     the JWKS. Rotation without these is an outage: every token signed by the old key fails
     *     verification the moment the new one takes over, and access tokens live for 15 minutes.
     */
    public record Signing(String privateKey, List<String> retiredPublicKeys) {
    }

    /**
     * @param bcryptStrength 12, the platform's setting. Imported MobiStack hashes were written at 12
     *     and platform's at 10; both verify regardless, because bcrypt stores the cost inside the
     *     hash. This only decides the cost of hashes written from now on.
     */
    public record Password(
            @DefaultValue("10") int minLength,
            @DefaultValue("12") int bcryptStrength) {
    }

    /**
     * @param maxFailedAttempts hardcoded at 5 in the platform. Configurable here because the number
     *     that stops credential stuffing and the number that stops locking out a legitimate user
     *     with a stale password manager entry are not obviously the same, and nobody could tune it.
     */
    public record Lockout(
            @DefaultValue("5") int maxFailedAttempts,
            @DefaultValue("PT15M") Duration duration) {
    }

    /** Magic links, OTPs, password resets and email verification. */
    public record Challenge(
            @DefaultValue("6") int otpLength,
            @DefaultValue("PT10M") Duration ttl,
            @DefaultValue("5") int maxAttempts) {
    }

    /**
     * @param domain the registrable parent domain, so every console hostname sees the same cookie.
     *     Empty means host-only, which is what you want in local development where there is no
     *     parent domain to share.
     * @param sameSite Lax, not None: the cookie is withheld from cross-site POSTs, so the exchange
     *     endpoint cannot be driven from another origin.
     */
    public record SessionCookie(
            @DefaultValue("pbx_session") String name,
            @DefaultValue("") String domain,
            @DefaultValue("true") boolean secure,
            @DefaultValue("Lax") String sameSite) {

        public String domainOrNull() {
            return domain == null || domain.isBlank() ? null : domain;
        }
    }

    /**
     * Where emailed links point.
     *
     * <p>These are console router paths, not API paths. The two drifted apart once already and every
     * emailed magic link 404'd, so they are configured as whole URLs rather than assembled from a
     * base and a guess.
     */
    public record Urls(String console, String admin) {
    }

    /** @param googleClientId blank disables Google sign-in rather than failing at request time */
    public record Sso(@DefaultValue("") String googleClientId) {
    }
}
