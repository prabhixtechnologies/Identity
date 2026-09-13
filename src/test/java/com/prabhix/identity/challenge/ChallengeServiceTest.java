package com.prabhix.identity.challenge;

import com.prabhix.identity.challenge.AuthChallenge.ChallengePurpose;
import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.config.TestProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ChallengeServiceTest {

    private final Map<UUID, AuthChallenge> rows = new HashMap<>();

    private AuthChallengeRepository challenges;
    private ChallengeService service;
    private UUID userId;

    @BeforeEach
    void setUp() {
        challenges = mock(AuthChallengeRepository.class);
        service = new ChallengeService(challenges, TestProperties.signing("", List.of()));
        userId = UUID.randomUUID();

        when(challenges.save(any(AuthChallenge.class))).thenAnswer(call -> {
            AuthChallenge challenge = call.getArgument(0);
            if (challenge.getId() == null) {
                challenge.setId(UUID.randomUUID());
            }
            if (challenge.getCreatedAt() == null) {
                challenge.setCreatedAt(Instant.now());
            }
            rows.put(challenge.getId(), challenge);
            return challenge;
        });
        when(challenges.findBySecretHashAndPurposeAndConsumedAtIsNull(any(), any()))
                .thenAnswer(call -> rows.values().stream()
                        .filter(row -> row.getSecretHash().equals(call.getArgument(0)))
                        .filter(row -> row.getPurpose() == call.getArgument(1))
                        .filter(row -> !row.isConsumed())
                        .findFirst());
        when(challenges.findFirstByDestinationAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(any(), any()))
                .thenAnswer(call -> rows.values().stream()
                        .filter(row -> row.getDestination().equals(call.getArgument(0)))
                        .filter(row -> row.getPurpose() == call.getArgument(1))
                        .filter(row -> !row.isConsumed())
                        .findFirst());
    }

    @Test
    @DisplayName("an OTP is numeric and the configured length; a link secret is neither")
    void secretShapeDependsOnPurpose() {
        String otp = service.raise(ChallengePurpose.EMAIL_OTP, userId, "a@b.com", null).rawSecret();
        String link = service.raise(ChallengePurpose.MAGIC_LINK, userId, "a@b.com", null).rawSecret();

        assertThat(otp).hasSize(6).containsOnlyDigits();
        // A link is not read aloud or retyped, so it can afford full entropy — and needs it, because
        // a wrong link costs no attempt.
        assertThat(link.length()).isGreaterThan(32);
    }

    @Test
    @DisplayName("only the hash of the secret is stored")
    void storesOnlyTheHash() {
        ChallengeService.Raised raised =
                service.raise(ChallengePurpose.MAGIC_LINK, userId, "a@b.com", "1.2.3.4");

        assertThat(raised.challenge().getSecretHash()).isNotEqualTo(raised.rawSecret());
        assertThat(raised.challenge().getIpAddress()).isEqualTo("1.2.3.4");
    }

    @Test
    @DisplayName("a link works once")
    void linkIsSingleUse() {
        String secret = service.raise(ChallengePurpose.MAGIC_LINK, userId, "a@b.com", null).rawSecret();

        assertThat(service.consumeBySecret(secret, ChallengePurpose.MAGIC_LINK).getConsumedAt())
                .isNotNull();

        // The repository filters consumed rows, so the second attempt cannot find it at all — which
        // is the same answer a made-up token gets, and reveals nothing about whether it ever existed.
        assertThat(catchApi(() -> service.consumeBySecret(secret, ChallengePurpose.MAGIC_LINK)).getCode())
                .isEqualTo(ErrorCode.TOKEN_INVALID);
    }

    @Test
    @DisplayName("a link raised for one purpose cannot be redeemed for another")
    void purposeIsPartOfTheLookup() {
        String reset = service.raise(ChallengePurpose.PASSWORD_RESET, userId, "a@b.com", null).rawSecret();

        // Without this a password-reset link would also sign you in, which matters because the two
        // are emailed on different triggers and one is reachable by anyone who knows an address.
        assertThat(catchApi(() -> service.consumeBySecret(reset, ChallengePurpose.MAGIC_LINK)).getCode())
                .isEqualTo(ErrorCode.TOKEN_INVALID);
    }

    @Test
    @DisplayName("an expired link is reported as expired, not as invalid")
    void expiredLink() {
        ChallengeService.Raised raised =
                service.raise(ChallengePurpose.MAGIC_LINK, userId, "a@b.com", null);
        raised.challenge().setExpiresAt(Instant.now().minusSeconds(1));

        // Different code because the remedy is different: request another one, rather than check
        // whether you followed the right link.
        assertThat(catchApi(() ->
                service.consumeBySecret(raised.rawSecret(), ChallengePurpose.MAGIC_LINK)).getCode())
                .isEqualTo(ErrorCode.OTP_EXPIRED);
    }

    @Test
    @DisplayName("a wrong OTP costs an attempt, and the ceiling ends the challenge")
    void otpAttemptsAreCounted() {
        ChallengeService.Raised raised =
                service.raise(ChallengePurpose.EMAIL_OTP, userId, "a@b.com", null);
        String wrong = raised.rawSecret().equals("000000") ? "111111" : "000000";

        for (int attempt = 1; attempt < 5; attempt++) {
            assertThat(catchApi(() ->
                    service.consumeByCode("a@b.com", wrong, ChallengePurpose.EMAIL_OTP)).getCode())
                    .isEqualTo(ErrorCode.OTP_INVALID);
            assertThat(raised.challenge().getAttempts()).isEqualTo(attempt);
        }

        assertThat(catchApi(() ->
                service.consumeByCode("a@b.com", wrong, ChallengePurpose.EMAIL_OTP)).getCode())
                .isEqualTo(ErrorCode.OTP_ATTEMPTS_EXCEEDED);

        // Six digits is a million guesses, which is minutes of work against a rate limiter alone.
        // The counter is the only thing that makes it not worth walking.
        assertThat(catchApi(() ->
                service.consumeByCode("a@b.com", raised.rawSecret(), ChallengePurpose.EMAIL_OTP)).getCode())
                .isEqualTo(ErrorCode.OTP_ATTEMPTS_EXCEEDED);
    }

    @Test
    @DisplayName("the right OTP consumes the challenge")
    void correctOtpConsumes() {
        ChallengeService.Raised raised =
                service.raise(ChallengePurpose.EMAIL_OTP, userId, "a@b.com", null);

        AuthChallenge consumed =
                service.consumeByCode("a@b.com", raised.rawSecret(), ChallengePurpose.EMAIL_OTP);

        assertThat(consumed.getConsumedAt()).isNotNull();
        assertThat(consumed.getUserId()).isEqualTo(userId);
    }

    @Test
    @DisplayName("a second challenge to the same destination is refused for 45 seconds")
    void raiseIsCooledDown() {
        service.raise(ChallengePurpose.EMAIL_OTP, userId, "a@b.com", null);

        assertThat(catchApi(() ->
                service.raise(ChallengePurpose.EMAIL_OTP, userId, "a@b.com", null)).getCode())
                .isEqualTo(ErrorCode.RATE_LIMITED);
    }

    @Test
    @DisplayName("an OTP for an address with no challenge is simply wrong")
    void unknownDestination() {
        when(challenges.findFirstByDestinationAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(
                eq("nobody@b.com"), any())).thenReturn(Optional.empty());

        assertThat(catchApi(() ->
                service.consumeByCode("nobody@b.com", "123456", ChallengePurpose.EMAIL_OTP)).getCode())
                .isEqualTo(ErrorCode.OTP_INVALID);
    }

    private ApiException catchApi(Runnable action) {
        try {
            action.run();
        } catch (ApiException ex) {
            return ex;
        }
        throw new AssertionError("Expected an ApiException, but the call succeeded");
    }
}
