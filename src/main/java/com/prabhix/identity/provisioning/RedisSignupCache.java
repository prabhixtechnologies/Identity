package com.prabhix.identity.provisioning;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

/** Redis backing for a pending signup. A cache outage refuses the signup rather than writing a user. */
@Slf4j
@Component
@RequiredArgsConstructor
class RedisSignupCache implements SignupCache {

    private final StringRedisTemplate redis;

    @Override
    public void put(String key, String value, Duration ttl) {
        try {
            redis.opsForValue().set(key, value, ttl);
        } catch (RuntimeException ex) {
            throw unavailable(ex);
        }
    }

    @Override
    public String get(String key) {
        try {
            return redis.opsForValue().get(key);
        } catch (RuntimeException ex) {
            throw unavailable(ex);
        }
    }

    @Override
    public long secondsLeft(String key) {
        try {
            Long seconds = redis.getExpire(key, TimeUnit.SECONDS);
            return seconds == null ? 0 : seconds;
        } catch (RuntimeException ex) {
            throw unavailable(ex);
        }
    }

    @Override
    public void delete(String... keys) {
        if (keys == null || keys.length == 0) {
            return;
        }
        // One key per command. ElastiCache Serverless rejects a multi-key delete when the
        // signup token and the address index land in different slots.
        RuntimeException failure = null;
        for (String key : keys) {
            if (key == null) {
                continue;
            }
            try {
                redis.delete(key);
            } catch (RuntimeException ex) {
                if (failure == null) {
                    failure = ex;
                }
            }
        }
        if (failure != null) {
            throw unavailable(failure);
        }
    }

    private static ApiException unavailable(RuntimeException ex) {
        Throwable cause = ex.getCause();
        log.warn("Signup cache unavailable: {}{}", ex,
                cause == null || cause == ex ? "" : " caused by " + cause);
        return ApiException.of(ErrorCode.DEPENDENCY_UNAVAILABLE,
                "Sign-up is temporarily unavailable. Try again in a moment.");
    }
}
