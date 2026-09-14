package com.prabhix.identity.client;

import jakarta.servlet.http.HttpServletRequest;

/** Reads the bearer token out of {@code Authorization}, or null when there is none. */
public final class BearerTokens {

    private static final String BEARER = "Bearer ";

    private BearerTokens() {
    }

    public static String from(HttpServletRequest request) {
        return from(request.getHeader("Authorization"));
    }

    public static String from(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.regionMatches(true, 0, BEARER, 0, BEARER.length())) {
            return null;
        }
        String token = authorizationHeader.substring(BEARER.length()).trim();
        return token.isEmpty() ? null : token;
    }
}
