package com.prabhix.identity.security.internal;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Which {@code /internal} routes are automated (service token only) versus staff-administration
 * (service token plus {@code X-Prabhix-Acting-User}).
 */
public final class InternalRoutePolicy {

    private InternalRoutePolicy() {
    }

    public static boolean isInternal(HttpServletRequest request) {
        String path = normalizePath(request.getRequestURI());
        return path.startsWith("/internal/");
    }

    /** Staff admin surface: every call must name the acting user. */
    public static boolean requiresActingUser(HttpServletRequest request) {
        String path = normalizePath(request.getRequestURI());
        return path.startsWith("/internal/identity/admin/");
    }

    /**
     * Product automation paths documented in {@code docs/SECURITY-FLOWS.md}: lookup, per-user
     * break-glass revocation, and fleet-wide cutover.
     */
    public static boolean isAutomatedServiceRoute(HttpServletRequest request) {
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            return false;
        }
        String path = normalizePath(request.getRequestURI());
        return path.equals("/internal/identity/users/lookup")
                || path.equals("/internal/identity/users/revoke-tokens")
                || path.equals("/internal/identity/sessions/revoke-all");
    }

    private static String normalizePath(String uri) {
        if (uri == null || uri.isBlank()) {
            return "";
        }
        int query = uri.indexOf('?');
        return query >= 0 ? uri.substring(0, query) : uri;
    }
}
