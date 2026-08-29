package com.prabhix.identity.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.List;

@ConfigurationProperties(prefix = "prabhix.identity")
public record IdentityProperties(String issuer, Token token, Signing signing) {

    /**
     * @param accessTokenTtl matches the platform's 15 minutes. Short because access tokens carry no
     *     revocation check of their own — a signature is valid until it expires, and the products
     *     verifying it offline cannot ask whether the session still exists.
     */
    public record Token(Duration accessTokenTtl) {
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
}
