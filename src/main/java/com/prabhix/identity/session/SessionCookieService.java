package com.prabhix.identity.session;

import com.prabhix.identity.common.Secrets;
import com.prabhix.identity.config.IdentityProperties;
import com.prabhix.identity.config.IdentityProperties.SessionCookie;
import com.prabhix.identity.web.AuthDtos.TokenResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * The browser half of a session: an opaque cookie on the parent domain that any Prabhix hostname can
 * exchange for an access token.
 *
 * <p>This exists because the console used to hold a refresh token in {@code localStorage}, which is
 * scoped to one origin. Two apps on two hostnames could not share it, and sharing the refresh token
 * itself would have been worse than useless: refresh tokens rotate, and presenting a used one is
 * treated as theft, so the two apps would have raced each other into revoking the session. A
 * credential that does not rotate can be exchanged concurrently by both apps as often as they like.
 *
 * <p>Now that identity is its own origin, the cookie is also what makes one sign-in cover OneOps, the
 * admin console, Mailroom and MobiStack: they share a registrable domain, so they share the cookie.
 *
 * <p>Servlet types stay in here rather than in {@link SignInService}, so the service that decides who
 * may sign in has no opinion about HTTP.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SessionCookieService {

    private final SessionService sessions;
    private final SignInService signIn;
    private final IdentityProperties properties;

    /**
     * Binds a fresh cookie to a session and writes it to the response.
     *
     * <p>Called on every flow that establishes a session. Overwriting any previous value is
     * intentional: signing in again on the same device should invalidate the credential the last
     * sign-in handed out.
     *
     * <p>Failure is swallowed on purpose. This is an enhancement to a sign-in that has already
     * succeeded — the caller is holding a valid access token by now — so a write failure here should
     * cost the user the shared session, not the login.
     */
    public void issue(HttpServletResponse response, UUID sessionId) {
        if (sessionId == null) {
            return;
        }
        try {
            String raw = Secrets.token();
            Instant expiresAt = Instant.now().plus(cookieTtl());
            sessions.bindCookie(sessionId, Secrets.sha256(raw), expiresAt);
            response.addHeader(HttpHeaders.SET_COOKIE, build(raw, cookieTtl()).toString());
        } catch (RuntimeException ex) {
            log.warn("Could not establish the shared session cookie for session {}: {}",
                    sessionId, ex.getMessage());
        }
    }

    /**
     * Exchanges the cookie on the request for a short-lived access token.
     *
     * <p>A cookie that no longer resolves is cleared from the browser as a side effect, so a
     * signed-out or expired session stops re-presenting a credential that can never work again.
     */
    public TokenResponse exchange(HttpServletRequest request, HttpServletResponse response) {
        String raw = read(request).orElseThrow(SignInService::noSessionCookie);
        try {
            return signIn.exchangeCookie(raw);
        } catch (RuntimeException ex) {
            clear(response);
            throw ex;
        }
    }

    /** Drops the cookie from the browser. Does not touch the row; logout already revokes it. */
    public void clear(HttpServletResponse response) {
        response.addHeader(HttpHeaders.SET_COOKIE, build("", Duration.ZERO).toString());
    }

    public Optional<String> read(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return Optional.empty();
        }
        String name = config().name();
        for (Cookie cookie : cookies) {
            if (name.equals(cookie.getName()) && cookie.getValue() != null && !cookie.getValue().isBlank()) {
                return Optional.of(cookie.getValue());
            }
        }
        return Optional.empty();
    }

    private ResponseCookie build(String value, Duration maxAge) {
        SessionCookie cookie = config();
        ResponseCookie.ResponseCookieBuilder builder = ResponseCookie.from(cookie.name(), value)
                // Unreadable from JavaScript. This is the whole security gain over localStorage: an
                // injected script can still call the API as the user, but it cannot exfiltrate a
                // credential that outlives the page it is running on.
                .httpOnly(true)
                .secure(cookie.secure())
                .path("/")
                .maxAge(maxAge)
                .sameSite(cookie.sameSite());

        String domain = cookie.domainOrNull();
        if (domain != null) {
            builder.domain(domain);
        }
        return builder.build();
    }

    private SessionCookie config() {
        return properties.sessionCookie();
    }

    /** One knob for "how long does a signed-in browser stay signed in", shared with refresh tokens. */
    private Duration cookieTtl() {
        return properties.token().refreshTokenTtl();
    }
}
