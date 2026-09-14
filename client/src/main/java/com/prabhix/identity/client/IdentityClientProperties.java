package com.prabhix.identity.client;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Where Prabhix Identity is, and how to talk to it.
 *
 * <p>Bound from {@code prabhix.identity.*}. Every product backend maps the same environment variables
 * onto these keys ({@code IDENTITY_ISSUER}, {@code IDENTITY_JWKS_URI}, {@code IDENTITY_INTERNAL_URL},
 * {@code IDENTITY_SERVICE_TOKEN}), so one compose file configures all of them identically.
 *
 * @param issuer the {@code iss} every accepted token must carry. Blank disables verification
 *     entirely: with no issuer there is nothing to trust, so every bearer token is refused.
 * @param jwksUri where the public keys are published. Defaults to the issuer's
 *     {@code /.well-known/jwks.json}; set explicitly when the issuer is a public host but the keys are
 *     fetched over the private network.
 * @param jwksCacheTtl how long a fetched key set is served before a background refresh.
 * @param jwksMinRefreshInterval the floor between two fetches, so an unknown {@code kid} in a
 *     forged token cannot be turned into a request to identity each time.
 * @param clockSkew tolerance applied to {@code exp} and {@code nbf}.
 * @param internalBaseUrl the private base URL of the internal API ({@code /internal/*}), reachable
 *     over the compose network and never through Caddy.
 * @param serviceToken the shared secret presented as {@code X-Prabhix-Service-Token}. Blank disables
 *     every internal call, which fails closed rather than sending a blank header.
 * @param internalTimeout per-call timeout for the internal API.
 */
@ConfigurationProperties("prabhix.identity")
public record IdentityClientProperties(
        String issuer,
        String jwksUri,
        Duration jwksCacheTtl,
        Duration jwksMinRefreshInterval,
        Duration clockSkew,
        String internalBaseUrl,
        String serviceToken,
        Duration internalTimeout) {

    public IdentityClientProperties {
        issuer = trimToNull(issuer);
        jwksUri = trimToNull(jwksUri);
        internalBaseUrl = stripTrailingSlash(trimToNull(internalBaseUrl));
        serviceToken = trimToNull(serviceToken);
        jwksCacheTtl = jwksCacheTtl == null ? Duration.ofMinutes(10) : jwksCacheTtl;
        jwksMinRefreshInterval = jwksMinRefreshInterval == null ? Duration.ofSeconds(30) : jwksMinRefreshInterval;
        clockSkew = clockSkew == null ? Duration.ofSeconds(30) : clockSkew;
        internalTimeout = internalTimeout == null ? Duration.ofSeconds(5) : internalTimeout;
    }

    /** Whether this deployment trusts an identity issuer at all. */
    public boolean enabled() {
        return issuer != null;
    }

    /** Whether the internal API can be called: it needs an address and a secret. */
    public boolean canCallInternal() {
        return internalBaseUrl != null && serviceToken != null;
    }

    public String effectiveJwksUri() {
        if (jwksUri != null) {
            return jwksUri;
        }
        return enabled() ? stripTrailingSlash(issuer) + "/.well-known/jwks.json" : null;
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static String stripTrailingSlash(String value) {
        if (value == null) {
            return null;
        }
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }
}
