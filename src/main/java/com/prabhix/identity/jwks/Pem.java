package com.prabhix.identity.jwks;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Reads RSA keys out of PEM text.
 *
 * <p>Deliberately without BouncyCastle: the JDK reads PKCS#8 private keys and X.509 public keys on
 * its own, and a signing service is the last place to add a cryptography dependency that does not
 * need to be there.
 */
final class Pem {

    private Pem() {
    }

    static RSAPrivateKey privateKey(String pem) {
        try {
            return (RSAPrivateKey) KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(der(pem)));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | ClassCastException ex) {
            throw new IllegalStateException(
                    "Signing key is not a PKCS#8 RSA private key. Generate one with: "
                            + "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048", ex);
        }
    }

    static RSAPublicKey publicKey(String pem) {
        try {
            return (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(der(pem)));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | ClassCastException ex) {
            throw new IllegalStateException("Retired key is not an X.509 RSA public key", ex);
        }
    }

    private static byte[] der(String pem) {
        // A PEM passed through a .env file or a container environment variable usually arrives with
        // its line breaks as the two characters backslash-n rather than as newlines. Stripping
        // whitespace alone would leave those in the middle of the base64 and fail to decode, with an
        // error that says nothing about the real cause.
        String body = pem.replace("\\n", "\n")
                .replaceAll("-----BEGIN [A-Z ]+-----", "")
                .replaceAll("-----END [A-Z ]+-----", "")
                .replaceAll("\\s", "");
        try {
            return Base64.getDecoder().decode(body);
        } catch (IllegalArgumentException ex) {
            throw new IllegalStateException(
                    "Key is not valid base64 between its PEM header and footer", ex);
        }
    }
}
