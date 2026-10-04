package com.prabhix.identity.session;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.config.IdentityProperties;

import java.time.Instant;

/**
 * Idle and absolute limits for one sign-in.
 *
 * <p>Activity slides the idle window. Nothing slides the absolute window: a year after the sign-in
 * that opened the row, the person signs in again even if they used the product every day.
 */
final class SessionLifetime {

    private final IdentityProperties.Token token;

    SessionLifetime(IdentityProperties properties) {
        this.token = properties.token();
    }

    void stampNewSession(DeviceSession session, Instant now) {
        if (session.getAbsoluteExpiresAt() == null) {
            session.setAbsoluteExpiresAt(now.plus(token.browserAbsoluteTtl()));
        }
    }

    void assertAlive(DeviceSession session, Instant now) {
        if (!session.isActive()) {
            throw ApiException.of(ErrorCode.TOKEN_REVOKED, "This session was signed out");
        }
        if (!absoluteDeadline(session, now).isAfter(now)) {
            throw ApiException.of(ErrorCode.TOKEN_EXPIRED,
                    "This sign-in has reached its one-year limit. Sign in again.");
        }
        Instant lastSeen = session.getLastSeenAt();
        if (lastSeen != null && lastSeen.plus(token.browserIdleTtl()).isBefore(now)) {
            throw ApiException.of(ErrorCode.TOKEN_EXPIRED,
                    "This sign-in has been idle too long. Sign in again.");
        }
    }

    Instant slidingCookieExpiry(DeviceSession session, Instant now) {
        return earlier(now.plus(token.browserIdleTtl()), absoluteDeadline(session, now));
    }

    Instant refreshExpiry(DeviceSession session, Instant now) {
        return earlier(now.plus(token.refreshTokenTtl()), absoluteDeadline(session, now));
    }

    Instant cookieGraceDeadline(Instant now) {
        return now.plus(token.cookieGrace());
    }

    private Instant absoluteDeadline(DeviceSession session, Instant now) {
        if (session.getAbsoluteExpiresAt() != null) {
            return session.getAbsoluteExpiresAt();
        }
        Instant start = session.getCreatedAt() != null ? session.getCreatedAt() : now;
        return start.plus(token.browserAbsoluteTtl());
    }

    private static Instant earlier(Instant left, Instant right) {
        return left.isBefore(right) ? left : right;
    }
}
