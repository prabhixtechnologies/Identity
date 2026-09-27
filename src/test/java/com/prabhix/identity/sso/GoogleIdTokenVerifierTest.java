package com.prabhix.identity.sso;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class GoogleIdTokenVerifierTest {

    private StringRedisTemplate redis;
    private ValueOperations<String, String> values;
    private GoogleIdTokenVerifier verifier;

    @BeforeEach
    void setUp() {
        redis = mock(StringRedisTemplate.class);
        values = mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(values);
        verifier = new GoogleIdTokenVerifier(redis);
    }

    @Test
    void rejectsReplayedTokens() {
        when(values.setIfAbsent(anyString(), eq("1"), any(Duration.class)))
                .thenReturn(true)
                .thenReturn(false);

        Instant expiresAt = Instant.now().plusSeconds(300);
        verifier.ensureNotReplayed("google-id-token", expiresAt);

        assertThatThrownBy(() -> verifier.ensureNotReplayed("google-id-token", expiresAt))
                .isInstanceOf(ApiException.class)
                .extracting(ex -> ((ApiException) ex).getCode())
                .isEqualTo(ErrorCode.INVALID_CREDENTIALS);
    }
}
