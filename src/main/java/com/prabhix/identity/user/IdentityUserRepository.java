package com.prabhix.identity.user;

import com.prabhix.identity.common.Emails;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface IdentityUserRepository extends JpaRepository<IdentityUser, UUID> {

    /**
     * Finds a live account by address, folding case for the caller.
     *
     * <p>Soft-deleted rows are excluded, which is what lets a deleted address be registered again.
     *
     * <p>Prefer this to the derived method it delegates to: {@code citext} does not make the
     * comparison case-insensitive on its own, for the reason spelled out in {@link Emails}.
     */
    default Optional<IdentityUser> findActiveByEmail(String email) {
        return findByEmailAndDeletedAtIsNull(Emails.normalize(email));
    }

    /** As {@link #findActiveByEmail}, for the registration check that only needs a yes or no. */
    default boolean activeEmailExists(String email) {
        return existsByEmailAndDeletedAtIsNull(Emails.normalize(email));
    }

    /**
     * Batch address lookup for a product mirroring users it only knows by email.
     *
     * <p>An {@code IN} list is safe here precisely because normalization happens in Java: were this
     * relying on {@code citext} to fold case it would have to be one query per address.
     */
    default List<IdentityUser> findActiveByEmails(Collection<String> emails) {
        return findByEmailInAndDeletedAtIsNull(emails.stream().map(Emails::normalize).toList());
    }

    /** Takes an already-normalized address. Call {@link #findActiveByEmail} instead. */
    Optional<IdentityUser> findByEmailAndDeletedAtIsNull(String email);

    /** Takes already-normalized addresses. Call {@link #findActiveByEmails} instead. */
    List<IdentityUser> findByEmailInAndDeletedAtIsNull(Collection<String> emails);

    /** Takes an already-normalized address. Call {@link #activeEmailExists} instead. */
    boolean existsByEmailAndDeletedAtIsNull(String email);

    Optional<IdentityUser> findByIdAndDeletedAtIsNull(UUID id);

    /**
     * Finds a live account by verified phone number, for SMS sign-in.
     *
     * <p>Verified only, deliberately. An unverified number is one somebody typed into a form, so
     * treating it as a way in would let anyone claim an account by entering its owner's number — the
     * verification step is the entire difference between a factor and an assertion.
     *
     * <p>Takes E.164 with no separators. {@code PhoneAuthService} normalizes, because the column is
     * plain {@code varchar} and {@code +91 98765 43210} would otherwise be a different number from
     * {@code +919876543210}.
     */
    Optional<IdentityUser> findByPhoneAndPhoneVerifiedAtIsNotNullAndDeletedAtIsNull(String phone);

    /** Batch lookup for a product filling in its local mirror after a token arrives. */
    List<IdentityUser> findByIdInAndDeletedAtIsNull(Collection<UUID> ids);
}
