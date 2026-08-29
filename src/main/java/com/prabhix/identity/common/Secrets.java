package com.prabhix.identity.common;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/** Generating and hashing the opaque secrets this service hands out. */
public final class Secrets {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final char[] DIGITS = "0123456789".toCharArray();

    private Secrets() {
    }

    /** 256 bits, URL-safe, for refresh tokens, session cookies and magic links. */
    public static String token() {
        byte[] buffer = new byte[32];
        RANDOM.nextBytes(buffer);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buffer);
    }

    /** Numeric OTP. {@link SecureRandom} because these gate account access. */
    public static String numericCode(int length) {
        StringBuilder builder = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            builder.append(DIGITS[RANDOM.nextInt(DIGITS.length)]);
        }
        return builder.toString();
    }

    /**
     * What gets stored for every opaque secret here.
     *
     * <p>Plain SHA-256 rather than bcrypt, and deliberately so: these values are 256 bits of
     * {@link SecureRandom} output, so there is no dictionary to slow an attacker down through and
     * nothing for a work factor to buy. Passwords are the opposite case and use bcrypt.
     */
    public static String sha256(String raw) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(raw.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable", ex);
        }
    }

    /**
     * Constant-time comparison, for checking a submitted OTP against a stored hash.
     *
     * <p>Both sides are hex of the same length so the early-exit in {@code String.equals} leaks
     * little, but an OTP is six digits and worth not measuring at all.
     */
    public static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}
