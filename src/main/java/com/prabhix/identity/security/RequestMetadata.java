package com.prabhix.identity.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Optional;

/** What the transport layer knows about the caller, for audit rows and device sessions. */
public final class RequestMetadata {

    private static final int IP_MAX = 45;
    private static final int USER_AGENT_MAX = 500;

    private RequestMetadata() {
    }

    /**
     * The caller's address as seen past the reverse proxy.
     *
     * <p>Only the first hop of {@code X-Forwarded-For} is taken, and only because Caddy sets it: the
     * header is client-supplied, so anything further along the chain is whatever the client wrote
     * there. It is used for rate limiting and for the audit trail, never for access decisions.
     */
    public static String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        String address = forwarded != null && !forwarded.isBlank()
                ? forwarded.split(",")[0].trim()
                : request.getRemoteAddr();
        return truncate(address, IP_MAX);
    }

    public static String userAgent(HttpServletRequest request) {
        return truncate(request.getHeader("User-Agent"), USER_AGENT_MAX);
    }

    /** The request bound to this thread, if there is one. Empty on a scheduler or test thread. */
    public static Optional<HttpServletRequest> current() {
        return RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes
                ? Optional.ofNullable(attributes.getRequest())
                : Optional.empty();
    }

    private static String truncate(String value, int max) {
        if (value == null) {
            return null;
        }
        return value.length() <= max ? value : value.substring(0, max);
    }
}
