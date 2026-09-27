package com.prabhix.identity.security;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.Emails;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.common.Secrets;
import com.prabhix.identity.config.IdentityProperties;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-IP, per-account and per-destination budgets for public authentication endpoints.
 *
 * <p>Redis is the primary store. When it is unavailable, a tight in-memory fallback applies on this
 * node only so auth endpoints still throttle credential stuffing rather than opening completely.
 */
@Slf4j
@Component
public class AuthRateLimiter {

    private static final String KEY_PREFIX = "pbx:identity:rl:";
    private static final Duration WINDOW = Duration.ofMinutes(1);

    public enum Bucket {
        LOGIN_IP,
        LOGIN_ACCOUNT,
        ISSUE_DESTINATION,
        VERIFY_IP
    }

    private final StringRedisTemplate redis;
    private final IdentityProperties properties;
    private final Counter redisDegraded;
    private final Map<String, DegradedWindow> degraded = new ConcurrentHashMap<>();

    public AuthRateLimiter(StringRedisTemplate redis, IdentityProperties properties) {
        this(redis, properties, new SimpleMeterRegistry());
    }

    @Autowired
    public AuthRateLimiter(StringRedisTemplate redis, IdentityProperties properties, MeterRegistry meters) {
        this.redis = redis;
        this.properties = properties;
        this.redisDegraded = Counter.builder("prabhix.identity.auth_rate_limit.redis_degraded")
                .description("Auth rate limiting fell back to in-memory buckets")
                .register(meters);
    }

    public void checkLogin(String ipAddress, String email) {
        if (!properties.rateLimit().enabled()) {
            return;
        }
        enforce(Bucket.LOGIN_IP, ipAddress, properties.rateLimit().loginAttemptsPerMinutePerIp());
        if (email != null && !email.isBlank()) {
            enforce(Bucket.LOGIN_ACCOUNT, Emails.normalize(email),
                    properties.rateLimit().loginAttemptsPerMinutePerAccount());
        }
    }

    public void checkIssue(String ipAddress, String destination) {
        if (!properties.rateLimit().enabled()) {
            return;
        }
        enforce(Bucket.LOGIN_IP, ipAddress, properties.rateLimit().loginAttemptsPerMinutePerIp());
        if (destination != null && !destination.isBlank()) {
            enforce(Bucket.ISSUE_DESTINATION, normalizeDestination(destination),
                    properties.rateLimit().issueAttemptsPerMinutePerDestination());
        }
    }

    public void checkVerify(String ipAddress) {
        if (!properties.rateLimit().enabled()) {
            return;
        }
        enforce(Bucket.VERIFY_IP, ipAddress, properties.rateLimit().verifyAttemptsPerMinutePerIp());
    }

    private void enforce(Bucket bucket, String rawKey, int limit) {
        if (rawKey == null || rawKey.isBlank()) {
            return;
        }
        String key = hashedKey(bucket, rawKey);
        long used = increment(key);
        if (used > limit) {
            throw ApiException.of(ErrorCode.RATE_LIMITED,
                    "Too many attempts. Wait a moment and try again.");
        }
    }

    private long increment(String key) {
        try {
            Long counter = redis.opsForValue().increment(key);
            long used = counter == null ? 1L : counter;
            if (used == 1L) {
                redis.expire(key, WINDOW);
            }
            return used;
        } catch (RuntimeException ex) {
            redisDegraded.increment();
            log.warn("Auth rate limiter degraded to in-memory fallback: {}", ex.getMessage());
            return degradedIncrement(key);
        }
    }

    private long degradedIncrement(String key) {
        int limit = properties.rateLimit().redisDegradedAttemptsPerMinutePerIp();
        DegradedWindow window = degraded.computeIfAbsent(key, ignored -> new DegradedWindow());
        return window.increment(limit);
    }

    private String hashedKey(Bucket bucket, String rawKey) {
        String pepper = properties.rateLimit().effectivePepper(properties.serviceToken());
        String digest = Secrets.sha256(pepper + ":" + bucket.name() + ":" + rawKey);
        return KEY_PREFIX + bucket.name().toLowerCase() + ":" + digest;
    }

    private static String normalizeDestination(String destination) {
        if (destination.contains("@")) {
            return Emails.normalize(destination);
        }
        return destination.trim();
    }

    private static final class DegradedWindow {
        private long windowStartMs = System.currentTimeMillis();
        private long count;

        synchronized long increment(int limit) {
            long now = System.currentTimeMillis();
            if (now - windowStartMs >= WINDOW.toMillis()) {
                windowStartMs = now;
                count = 0;
            }
            count++;
            if (count > limit) {
                throw ApiException.of(ErrorCode.RATE_LIMITED,
                        "Too many attempts. Wait a moment and try again.");
            }
            return count;
        }
    }
}
