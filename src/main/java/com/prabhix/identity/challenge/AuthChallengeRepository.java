package com.prabhix.identity.challenge;

import com.prabhix.identity.challenge.AuthChallenge.ChallengePurpose;
import com.prabhix.identity.common.Emails;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface AuthChallengeRepository extends JpaRepository<AuthChallenge, UUID> {

    Optional<AuthChallenge> findBySecretHashAndPurposeAndConsumedAtIsNull(
            String secretHash, ChallengePurpose purpose);

    /**
     * The newest unconsumed challenge for an address, used by OTP verification where the caller
     * supplies a code rather than a link and so cannot be looked up by hash directly.
     *
     * <p>Folds case for the caller, because {@code citext} does not — see {@link Emails}.
     */
    default Optional<AuthChallenge> findNewestUnconsumed(String destination, ChallengePurpose purpose) {
        return findFirstByDestinationAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(
                Emails.normalize(destination), purpose);
    }

    /** Takes an already-normalized destination. Call {@link #findNewestUnconsumed} instead. */
    Optional<AuthChallenge> findFirstByDestinationAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(
            String destination, ChallengePurpose purpose);
}
