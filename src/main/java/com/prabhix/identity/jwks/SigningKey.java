package com.prabhix.identity.jwks;

import io.jsonwebtoken.security.Jwks;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * The active signing key pair and the {@code kid} that identifies it in the JWKS.
 *
 * @param privateKey never leaves this service
 * @param publicKey published, so products verify without being able to sign
 */
public record SigningKey(RSAPrivateKey privateKey, RSAPublicKey publicKey, String keyId) {

    SigningKey(RSAPrivateKey privateKey, RSAPublicKey publicKey) {
        this(privateKey, publicKey, thumbprint(publicKey));
    }

    /**
     * The key id every token's header carries, so a client knows which published key to verify with
     * and a rotation does not require it to guess.
     */
    private static String thumbprint(RSAPublicKey publicKey) {
        return Jwks.builder().key(publicKey).idFromThumbprint().build().getId();
    }
}
