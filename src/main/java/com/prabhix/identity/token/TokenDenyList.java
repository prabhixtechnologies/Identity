package com.prabhix.identity.token;

import com.prabhix.identity.config.IdentityProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * Immediate revocation for tokens that have not expired yet.
 *
 * <p>Access tokens are self-contained, which is what keeps the hot path fast and lets a product
 * verify one without asking us anything. It also means a logout or a password change cannot
 * invalidate one on its own. Entries here live only as long as the access-token TTL, so the list
 * holds "recently revoked" rather than "all revoked ever".
 *
 * <p><b>The keys are shared, on purpose.</b> They are byte-identical to the platform's — same
 * {@code pbx:deny:} prefix, same Redis — because identity writes revocations and every product reads
 * them. Renaming a key here without renaming it in each product would silently stop revocation
 * working while every health check stayed green.
 *
 * <p>Two scopes, deliberately different:
 *
 * <ul>
 *   <li><b>Session</b> entries deny outright. A session id is fixed for the life of that session and
 *       a new sign-in mints a new one, so no legitimate later token can carry a revoked session id.
 *   <li><b>User</b> entries deny only tokens issued <em>before</em> the revocation. They must not
 *       deny outright: signing in again is the expected response to a password change, and the new
 *       token would otherwise be rejected for the rest of the TTL.
 * </ul>
 *
 * <p>Redis being unavailable must not lock everyone out, so lookups fail open and log. The exposure
 * is bounded by the 15-minute TTL, which is a better trade than a total outage.
 */
@Slf4j
@Component
public class TokenDenyList {

    private static final String SESSION_KEY = "pbx:deny:session:";
    private static final String USER_KEY = "pbx:deny:user:";

    /** 2001-09-09. Below this a stored value is a marker from an older build, not a timestamp. */
    private static final long MIN_PLAUSIBLE_EPOCH_MILLIS = 1_000_000_000_000L;

    private final StringRedisTemplate redis;
    private final Duration ttl;

    public TokenDenyList(StringRedisTemplate redis, IdentityProperties properties) {
        this.redis = redis;
        this.ttl = properties.token().accessTokenTtl();
    }

    /** Revokes one device session, e.g. on logout or "sign out this device". */
    public void revokeSession(UUID sessionId) {
        if (sessionId == null) {
            return;
        }
        write(SESSION_KEY + sessionId, "1");
    }

    /**
     * Revokes every session for a user: password change, or being disabled. Cheaper and safer than
     * enumerating their sessions.
     */
    public void revokeUser(UUID userId) {
        if (userId == null) {
            return;
        }
        write(USER_KEY + userId, Long.toString(Instant.now().toEpochMilli()));
    }

    /**
     * @param issuedAt the token's {@code iat}. A null value is treated as "older than any
     *     revocation", because a token we cannot date is not one to trust against a pending
     *     revocation.
     */
    public boolean isRevoked(UUID userId, UUID sessionId, Instant issuedAt) {
        try {
            if (sessionId != null && Boolean.TRUE.equals(redis.hasKey(SESSION_KEY + sessionId))) {
                return true;
            }
            if (userId == null) {
                return false;
            }
            String revokedAt = redis.opsForValue().get(USER_KEY + userId);
            if (revokedAt == null) {
                return false;
            }
            return issuedBefore(issuedAt, revokedAt);
        } catch (RuntimeException ex) {
            log.warn("Deny-list check failed, allowing the request through: {}", ex.getMessage());
            return false;
        }
    }

    private boolean issuedBefore(Instant issuedAt, String revokedAt) {
        if (issuedAt == null) {
            return true;
        }
        long revokedAtMillis;
        try {
            revokedAtMillis = Long.parseLong(revokedAt);
        } catch (NumberFormatException ex) {
            return true;
        }
        // The platform stores "1" for a session revocation under a different key, but an older
        // platform build stored it under the user key too. That parses as 1970 and would deny
        // nothing, so anything below the floor is treated as a revocation until the entry ages out.
        if (revokedAtMillis < MIN_PLAUSIBLE_EPOCH_MILLIS) {
            return true;
        }
        // Not strictly before: iat has second precision, so a token minted in the same second as
        // the revocation cannot be ordered against it. Denying is the fail-safe direction, and
        // costs at most a retry one second later.
        return issuedAt.toEpochMilli() <= revokedAtMillis;
    }

    private void write(String key, String value) {
        try {
            redis.opsForValue().set(key, value, ttl);
        } catch (RuntimeException ex) {
            // Logged loudly: a dropped revocation is a real security event, not noise.
            log.error("Could not write deny-list entry {}. Revocation will lag until the token expires.",
                    key, ex);
        }
    }
}
