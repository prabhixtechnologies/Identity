package com.prabhix.identity.client;

import jakarta.servlet.http.HttpServletRequest;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Optional;
import java.util.UUID;

/**
 * Checks the shared service token on a product's own {@code /internal/*} endpoints.
 *
 * <p>The same secret identity checks on its side, so one value in the environment authenticates
 * every service-to-service hop. A blank configured token disables the endpoints rather than
 * accepting a blank header: a deployment that forgot to set one fails closed.
 */
public class ServiceTokenGuard {

    private final String expected;

    public ServiceTokenGuard(IdentityClientProperties config) {
        this.expected = config.serviceToken();
    }

    public boolean configured() {
        return expected != null && !expected.isBlank();
    }

    /** Whether the request carries the right token. Never throws; the caller picks the response. */
    public boolean permits(HttpServletRequest request) {
        if (!configured()) {
            return false;
        }
        String presented = request.getHeader(IdentityInternalClient.SERVICE_TOKEN_HEADER);
        return presented != null && constantTimeEquals(expected, presented);
    }

    /** The staff member a BFF call is being made for, if the caller named one. */
    public Optional<UUID> actingUser(HttpServletRequest request) {
        String raw = request.getHeader(IdentityInternalClient.ACTING_USER_HEADER);
        if (raw == null || raw.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.of(UUID.fromString(raw.trim()));
        } catch (IllegalArgumentException ex) {
            return Optional.empty();
        }
    }

    public Optional<String> actingReason(HttpServletRequest request) {
        String raw = request.getHeader(IdentityInternalClient.ACTING_REASON_HEADER);
        return raw == null || raw.isBlank() ? Optional.empty() : Optional.of(raw.trim());
    }

    static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}
