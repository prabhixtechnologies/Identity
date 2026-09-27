package com.prabhix.identity.security.internal;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.common.Secrets;
import com.prabhix.identity.config.IdentityProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/** Throttles repeated bad service-token attempts on {@code /internal}. */
@Slf4j
@Component
public class InternalFailedAuthRateLimiter {

    private static final String KEY_PREFIX = "pbx:identity:internal:fail:";
    private static final Duration WINDOW = Duration.ofMinutes(1);
    private static final int LIMIT_PER_MINUTE = 30;
    private static final int DEGRADED_LIMIT = 5;

    private final StringRedisTemplate redis;
    private final IdentityProperties properties;
    private final Map<String, DegradedWindow> degraded = new ConcurrentHashMap<>();

    public InternalFailedAuthRateLimiter(StringRedisTemplate redis, IdentityProperties properties) {
        this.redis = redis;
        this.properties = properties;
    }

    public void recordFailure(String clientKey, String presentedToken) {
        enforce(clientKey);
        if (presentedToken != null && !presentedToken.isBlank()) {
            enforce("token:" + Secrets.sha256(presentedToken));
        }
    }

    private void enforce(String rawKey) {
        String key = KEY_PREFIX + Secrets.sha256(pepper() + ":" + rawKey);
        long used = increment(key);
        if (used > LIMIT_PER_MINUTE) {
            throw ApiException.of(ErrorCode.RATE_LIMITED,
                    "Too many invalid internal requests. Wait a moment and try again.");
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
            log.warn("Internal auth rate limiter degraded: {}", ex.getMessage());
            return degradedIncrement(key);
        }
    }

    private long degradedIncrement(String key) {
        DegradedWindow window = degraded.computeIfAbsent(key, ignored -> new DegradedWindow());
        return window.increment(DEGRADED_LIMIT);
    }

    private String pepper() {
        return properties.rateLimit().effectivePepper(properties.serviceToken());
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
                        "Too many invalid internal requests. Wait a moment and try again.");
            }
            return count;
        }
    }
}
