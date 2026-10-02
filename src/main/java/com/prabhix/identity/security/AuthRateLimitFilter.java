package com.prabhix.identity.security;

import com.prabhix.identity.common.ApiError;
import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import tools.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Applies {@link AuthRateLimiter} to public authentication HTTP endpoints.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 20)
@RequiredArgsConstructor
public class AuthRateLimitFilter extends OncePerRequestFilter {

    private static final Set<String> ROUTINE_AUTH = Set.of(
            "/api/v1/identity/auth/session/token");

    private static final Pattern EMAIL_FIELD =
            Pattern.compile("\"email\"\\s*:\\s*\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);
    private static final Pattern PHONE_FIELD =
            Pattern.compile("\"phone\"\\s*:\\s*\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);

    private final AuthRateLimiter limiter;
    private final TrustedClientIpResolver clientIp;
    private final ObjectMapper objectMapper;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return classify(request) == Kind.NONE;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        HttpServletRequest wrapped = request;
        if (request.getContentType() != null && request.getContentType().contains("json")) {
            wrapped = new ContentCachingRequestWrapper(request, 4096);
        }
        try {
            apply(wrapped);
            chain.doFilter(wrapped, response);
        } catch (ApiException ex) {
            if (ex.getCode() != ErrorCode.RATE_LIMITED) {
                throw ex;
            }
            response.setStatus(ErrorCode.RATE_LIMITED.status().value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.setHeader("Retry-After", "60");
            objectMapper.writeValue(response.getOutputStream(), ApiError.of(
                    ErrorCode.RATE_LIMITED,
                    ex.getMessage(),
                    null,
                    request.getRequestURI()));
        }
    }

    private void apply(HttpServletRequest request) {
        Kind kind = classify(request);
        String ip = clientIp.resolve(request);
        String email = parameter(request, "email", "username");
        String destination = email;
        if (destination == null || destination.isBlank()) {
            destination = parameter(request, "phone");
        }
        if ((destination == null || destination.isBlank()) && request instanceof ContentCachingRequestWrapper cached) {
            destination = jsonField(cached, EMAIL_FIELD);
            if (destination == null) {
                destination = jsonField(cached, PHONE_FIELD);
            }
            if (email == null || email.isBlank()) {
                email = destination;
            }
        }
        switch (kind) {
            case LOGIN -> limiter.checkLogin(ip, email);
            case ISSUE -> limiter.checkIssue(ip, destination);
            case VERIFY -> limiter.checkVerify(ip);
            default -> {
            }
        }
    }

    private static Kind classify(HttpServletRequest request) {
        String path = request.getRequestURI();
        String method = request.getMethod();
        if (path == null || method == null) {
            return Kind.NONE;
        }
        if (ROUTINE_AUTH.contains(path)) {
            return Kind.NONE;
        }
        if (path.startsWith("/api/v1/identity/auth/")) {
            if ("POST".equalsIgnoreCase(method)) {
                if (path.endsWith("/login") || path.endsWith("/register") || path.endsWith("/sso/google")) {
                    return Kind.LOGIN;
                }
                if (path.contains("/request") || path.endsWith("/forgot")) {
                    return Kind.ISSUE;
                }
                if (path.contains("/verify") || path.endsWith("/reset") || path.contains("/confirm")) {
                    return Kind.VERIFY;
                }
            }
            return Kind.NONE;
        }
        if (!"POST".equalsIgnoreCase(method)) {
            return Kind.NONE;
        }
        if ("/login".equals(path) || path.startsWith("/login/")
                || "/signup".equals(path) || path.startsWith("/signup/")) {
            if (path.contains("/verify") || path.endsWith("/google") || "/login".equals(path)) {
                return Kind.LOGIN;
            }
            if (path.contains("/link") || path.contains("/code") || path.contains("/phone")
                    || path.contains("/whatsapp") || path.startsWith("/signup")) {
                return Kind.ISSUE;
            }
        }
        return Kind.NONE;
    }

    private static String parameter(HttpServletRequest request, String... names) {
        for (String name : names) {
            String value = request.getParameter(name);
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return null;
    }

    private static String jsonField(ContentCachingRequestWrapper request, Pattern pattern) {
        byte[] body = request.getContentAsByteArray();
        if (body.length == 0) {
            return null;
        }
        Charset charset = request.getCharacterEncoding() == null
                ? StandardCharsets.UTF_8
                : Charset.forName(request.getCharacterEncoding());
        var matcher = pattern.matcher(new String(body, charset));
        return matcher.find() ? matcher.group(1).trim() : null;
    }

    private enum Kind {
        NONE, LOGIN, ISSUE, VERIFY
    }
}
