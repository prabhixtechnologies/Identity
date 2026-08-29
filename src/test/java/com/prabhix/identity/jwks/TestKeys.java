package com.prabhix.identity.jwks;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Generates RSA keys and encodes them the way configuration supplies them, so the tests exercise
 * {@link Pem} rather than bypassing it with a key object.
 */
public final class TestKeys {

    private TestKeys() {
    }

    public static KeyPair pair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    /** PKCS#8, which is what {@code openssl genpkey} writes and what the JDK exports. */
    public static String privatePem(KeyPair pair) {
        return wrap("PRIVATE KEY", pair.getPrivate().getEncoded());
    }

    /** X.509 SubjectPublicKeyInfo, as {@code openssl rsa -pubout} writes. */
    public static String publicPem(KeyPair pair) {
        return wrap("PUBLIC KEY", pair.getPublic().getEncoded());
    }

    private static String wrap(String label, byte[] der) {
        return "-----BEGIN " + label + "-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der)
                + "\n-----END " + label + "-----\n";
    }
}
