package com.prabhix.identity.provisioning;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.provisioning.PendingSignupStore.Draft;
import com.prabhix.identity.provisioning.PendingSignupStore.Issued;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PendingSignupStoreTest {

    private MutableClock clock;
    private MemorySignupCache cache;
    private PendingSignupStore store;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-10-18T03:00:00Z"));
        cache = new MemorySignupCache();
        store = new PendingSignupStore(cache, Duration.ofMinutes(10), 6, 5, clock);
    }

    @Test
    void holdsTheSignupWithoutTheRawPasswordOrCode() {
        Issued issued = store.begin("Owner@Example.com", "Owner", "Acme", "$2a$04$hash");

        assertThat(store.address(issued.token())).isEqualTo("owner@example.com");
        String stored = cache.values.get(PendingSignupStore.PREFIX + issued.token());
        assertThat(stored).doesNotContain(issued.code());
        assertThat(stored).contains("$2a$04$hash");
        assertThat(cache.values.get(PendingSignupStore.EMAIL_PREFIX + "owner@example.com")).isNull();
    }

    @Test
    void matchingCodeReturnsTheDraftAndLeavesItUntilDiscard() {
        Issued issued = store.begin("owner@example.com", "Owner", "  ", "$hash");

        Draft draft = store.match(issued.token(), issued.code());

        assertThat(draft.email()).isEqualTo("owner@example.com");
        assertThat(draft.name()).isEqualTo("Owner");
        assertThat(draft.organization()).isNull();
        assertThat(draft.passwordHash()).isEqualTo("$hash");
        assertThat(store.address(issued.token())).isEqualTo("owner@example.com");

        store.discard(issued.token());

        assertThat(store.address(issued.token())).isNull();
    }

    @Test
    void wrongCodeDoesNotCreateAWayInAndFiveFailuresDropTheHold() {
        Issued issued = store.begin("owner@example.com", "Owner", null, "$hash");

        for (int attempt = 1; attempt <= 4; attempt++) {
            assertThatThrownBy(() -> store.match(issued.token(), "nope"))
                    .isInstanceOf(ApiException.class)
                    .extracting(ex -> ((ApiException) ex).getCode())
                    .isEqualTo(ErrorCode.OTP_INVALID);
            assertThat(store.address(issued.token())).isEqualTo("owner@example.com");
        }

        assertThatThrownBy(() -> store.match(issued.token(), "nope"))
                .isInstanceOf(ApiException.class)
                .extracting(ex -> ((ApiException) ex).getCode())
                .isEqualTo(ErrorCode.OTP_ATTEMPTS_EXCEEDED);
        assertThat(store.address(issued.token())).isNull();
    }

    @Test
    void aMissingHoldHasExpired() {
        assertThatThrownBy(() -> store.match("not-a-real-signup-token-value", "123456"))
                .isInstanceOf(ApiException.class)
                .extracting(ex -> ((ApiException) ex).getCode())
                .isEqualTo(ErrorCode.OTP_EXPIRED);
    }

    @Test
    void resendReplacesTheCodeAndRestartsTheHold() {
        Issued first = store.begin("owner@example.com", "Owner", "Acme", "$hash");
        clock.instant = clock.instant.plusSeconds(46);

        Issued second = store.resend(first.token());

        assertThat(second.code()).isNotEqualTo(first.code());
        assertThatThrownBy(() -> store.match(first.token(), first.code()))
                .isInstanceOf(ApiException.class)
                .extracting(ex -> ((ApiException) ex).getCode())
                .isEqualTo(ErrorCode.OTP_INVALID);
        assertThat(store.match(first.token(), second.code()).organization()).isEqualTo("Acme");
    }

    @Test
    void startingAgainDropsThePreviousCode() {
        Issued first = store.begin("owner@example.com", "Owner", null, "$hash");
        Issued second = store.begin("owner@example.com", "Owner", null, "$hash");

        assertThat(store.address(first.token())).isNull();
        assertThat(store.match(second.token(), second.code()).email()).isEqualTo("owner@example.com");
    }

    @Test
    void resendTooSoonIsRefused() {
        Issued issued = store.begin("owner@example.com", "Owner", null, "$hash");

        assertThatThrownBy(() -> store.resend(issued.token()))
                .isInstanceOf(ApiException.class)
                .extracting(ex -> ((ApiException) ex).getCode())
                .isEqualTo(ErrorCode.RATE_LIMITED);
    }

    private static final class MutableClock extends Clock {
        private Instant instant;

        private MutableClock(Instant instant) {
            this.instant = instant;
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }

    private static final class MemorySignupCache implements SignupCache {
        private final Map<String, String> values = new HashMap<>();
        private final Map<String, Instant> expires = new HashMap<>();

        @Override
        public void put(String key, String value, Duration ttl) {
            values.put(key, value);
            expires.put(key, Instant.now().plus(ttl));
        }

        @Override
        public String get(String key) {
            Instant deadline = expires.get(key);
            if (deadline == null || !deadline.isAfter(Instant.now())) {
                values.remove(key);
                expires.remove(key);
                return null;
            }
            return values.get(key);
        }

        @Override
        public long secondsLeft(String key) {
            Instant deadline = expires.get(key);
            if (deadline == null) {
                return 0;
            }
            return Math.max(0, Duration.between(Instant.now(), deadline).toSeconds());
        }

        @Override
        public void delete(String... keys) {
            for (String key : keys) {
                values.remove(key);
                expires.remove(key);
            }
        }
    }
}
