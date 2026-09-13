package com.prabhix.identity.challenge;

import com.prabhix.identity.challenge.AuthChallenge.ChallengePurpose;
import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.Emails;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.common.Secrets;
import com.prabhix.identity.config.IdentityProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * Raising and consuming one-time secrets, shared by every challenge-based flow.
 *
 * <p>Split out from the flows themselves because the checks that make a one-time secret one-time —
 * expiry, attempt ceiling, consumption — are the part that must not vary between magic links, OTPs,
 * resets and verification, and in the platform each flow re-implemented them slightly differently.
 */
@Service
@RequiredArgsConstructor
public class ChallengeService {

    private final AuthChallengeRepository challenges;
    private final IdentityProperties properties;

    private static final Duration RAISE_COOLDOWN = Duration.ofSeconds(45);

    /** @return the raw secret, which exists nowhere else — only its hash is stored */
    @Transactional
    public Raised raise(ChallengePurpose purpose, UUID userId, String destination, String ipAddress) {
        if (destination != null && !destination.isBlank()) {
            challenges.findFirstByDestinationAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(
                            Emails.normalize(destination), purpose)
                    .ifPresent(existing -> {
                        Instant created = existing.getCreatedAt();
                        if (created != null && created.isAfter(Instant.now().minus(RAISE_COOLDOWN))) {
                            throw ApiException.of(ErrorCode.RATE_LIMITED,
                                    "Wait a moment before requesting another code.");
                        }
                    });
        }
        // A short numeric code for anything typed back in by hand, a long random token for anything
        // clicked. Sending a 256-bit token by SMS would be unusable, and putting a six-digit code in a
        // link would be guessable by anyone who wanted to try a million of them.
        String raw = purpose.isCode()
                ? Secrets.numericCode(properties.challenge().otpLength())
                : Secrets.token();

        AuthChallenge challenge = new AuthChallenge();
        challenge.setPurpose(purpose);
        challenge.setUserId(userId);
        challenge.setDestination(Emails.normalize(destination));
        challenge.setSecretHash(Secrets.sha256(raw));
        challenge.setExpiresAt(Instant.now().plus(properties.challenge().ttl()));
        challenge.setMaxAttempts(properties.challenge().maxAttempts());
        challenge.setIpAddress(ipAddress);
        return new Raised(challenges.save(challenge), raw);
    }

    /**
     * Consumes a challenge identified by its secret, as a link-based flow does.
     *
     * <p>The lookup is by hash, so a wrong value finds nothing and there is no attempt to count
     * against — guessing 256 bits is not a threat model. The attempt ceiling still applies, because a
     * challenge can be found and then fail a later check.
     */
    @Transactional
    public AuthChallenge consumeBySecret(String rawSecret, ChallengePurpose purpose) {
        AuthChallenge challenge = challenges
                .findBySecretHashAndPurposeAndConsumedAtIsNull(Secrets.sha256(rawSecret), purpose)
                .orElseThrow(() -> ApiException.of(ErrorCode.TOKEN_INVALID, "That link is not valid"));
        return consume(challenge, "link");
    }

    /**
     * Consumes the newest challenge for an address after checking a submitted code, as OTP does.
     *
     * <p>A wrong code costs an attempt here, unlike {@link #consumeBySecret}: six digits is a space
     * small enough to walk, and the counter is the only thing that makes it not worth walking.
     */
    @Transactional
    public AuthChallenge consumeByCode(String destination, String code, ChallengePurpose purpose) {
        AuthChallenge challenge = challenges
                .findFirstByDestinationAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(destination, purpose)
                .orElseThrow(() -> ApiException.of(ErrorCode.OTP_INVALID, "That code is not correct"));

        if (challenge.isExpired()) {
            throw ApiException.of(ErrorCode.OTP_EXPIRED, "That code has expired");
        }
        if (challenge.isOutOfAttempts()) {
            throw tooManyAttempts();
        }

        if (!Secrets.constantTimeEquals(challenge.getSecretHash(), Secrets.sha256(code))) {
            challenge.setAttempts(challenge.getAttempts() + 1);
            challenges.save(challenge);
            throw challenge.isOutOfAttempts()
                    ? tooManyAttempts()
                    : ApiException.of(ErrorCode.OTP_INVALID, "That code is not correct");
        }

        return consume(challenge, "code");
    }

    private AuthChallenge consume(AuthChallenge challenge, String kind) {
        if (challenge.isExpired()) {
            throw ApiException.of(ErrorCode.OTP_EXPIRED, "That " + kind + " has expired");
        }
        if (challenge.isOutOfAttempts()) {
            throw tooManyAttempts();
        }
        if (challenge.isConsumed()) {
            throw ApiException.of(ErrorCode.CONFLICT, "That " + kind + " was already used");
        }
        challenge.setConsumedAt(Instant.now());
        return challenges.save(challenge);
    }

    private ApiException tooManyAttempts() {
        return ApiException.of(ErrorCode.OTP_ATTEMPTS_EXCEEDED, "Too many attempts. Request a new code.");
    }

    public long expiryMinutes() {
        return properties.challenge().ttl().toMinutes();
    }

    public record Raised(AuthChallenge challenge, String rawSecret) {
    }
}
