package com.prabhix.identity.security;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.config.TestProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthRateLimiterTest {

    private AuthRateLimiter limiter;

    @BeforeEach
    void setUp() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        ValueOperations<String, String> values = mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(values);
        ConcurrentHashMap<String, AtomicLong> counters = new ConcurrentHashMap<>();
        when(values.increment(anyString())).thenAnswer(invocation -> {
            String key = invocation.getArgument(0);
            return counters.computeIfAbsent(key, ignored -> new AtomicLong()).incrementAndGet();
        });
        limiter = new AuthRateLimiter(redis, TestProperties.signing("", List.of()));
    }

    @Test
    void blocksAfterTheConfiguredLoginBudget() {
        for (int i = 0; i < 10; i++) {
            limiter.checkLogin("198.51.100.4", "owner@example.com");
        }

        assertThatThrownBy(() -> limiter.checkLogin("198.51.100.4", "owner@example.com"))
                .isInstanceOf(ApiException.class)
                .extracting(ex -> ((ApiException) ex).getCode())
                .isEqualTo(ErrorCode.RATE_LIMITED);
    }

    @Test
    void fallsBackWhenRedisIsUnavailable() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        ValueOperations<String, String> values = mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(values);
        when(values.increment(anyString())).thenThrow(new RuntimeException("down"));
        AuthRateLimiter degraded = new AuthRateLimiter(redis, TestProperties.signing("", List.of()));

        degraded.checkLogin("198.51.100.4", "owner@example.com");
        degraded.checkLogin("198.51.100.4", "owner@example.com");
        degraded.checkLogin("198.51.100.4", "owner@example.com");

        assertThatThrownBy(() -> degraded.checkLogin("198.51.100.4", "owner@example.com"))
                .isInstanceOf(ApiException.class)
                .extracting(ex -> ((ApiException) ex).getCode())
                .isEqualTo(ErrorCode.RATE_LIMITED);
    }
}
