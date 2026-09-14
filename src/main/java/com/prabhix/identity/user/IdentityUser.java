package com.prabhix.identity.user;

import com.prabhix.identity.common.BaseEntity;
import com.prabhix.identity.common.Emails;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

/**
 * A person, independent of any product they use.
 *
 * <p>Named {@code IdentityUser} rather than {@code User} on purpose. Every product also has a
 * {@code User} — a thin mirror of this row that its foreign keys point at — and reading a stack
 * trace or an import script is much easier when the two cannot be confused for each other.
 *
 * <p>Deliberately absent: any notion of organization, shop, workspace, role or permission. Those
 * differ per product, and a column here that only one product can fill is product state in the
 * identity store.
 */
@Getter
@Setter
@Entity
@Table(name = "users")
public class IdentityUser extends BaseEntity {

    @Column(name = "email", nullable = false, columnDefinition = "citext")
    private String email;

    /** Normalizes, so no caller can put a mixed-case address in the table. See {@link Emails}. */
    public void setEmail(String email) {
        this.email = Emails.normalize(email);
    }

    @Column(name = "email_verified_at")
    private Instant emailVerifiedAt;

    @Column(name = "phone", length = 32)
    private String phone;

    @Column(name = "phone_verified_at")
    private Instant phoneVerifiedAt;

    /** Null for an account that has only ever signed in by magic link, OTP or SSO. */
    @Column(name = "password_hash", length = 120)
    private String passwordHash;

    @Column(name = "password_changed_at")
    private Instant passwordChangedAt;

    @Column(name = "full_name", nullable = false, length = 160)
    private String fullName;

    @Column(name = "display_name", length = 80)
    private String displayName;

    @Column(name = "avatar_url", length = 500)
    private String avatarUrl;

    @Column(name = "job_title", length = 120)
    private String jobTitle;

    @Column(name = "timezone", nullable = false, length = 64)
    private String timezone = "Asia/Kolkata";

    @Column(name = "locale", nullable = false, length = 16)
    private String locale = "en-IN";

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 24)
    private UserStatus status = UserStatus.ACTIVE;

    /**
     * Prabhix staff, not a customer's administrator.
     *
     * <p>It lives here rather than in a product because it is a fact about the person, and because
     * the admin console and the operator app both need it before either has picked a tenant. It is
     * still only a claim: each product decides for itself what a platform admin may do.
     */
    @Column(name = "platform_admin", nullable = false)
    private boolean platformAdmin;

    @Column(name = "failed_login_attempts", nullable = false)
    private int failedLoginAttempts;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    @Column(name = "last_login_at")
    private Instant lastLoginAt;

    @Column(name = "last_active_at")
    private Instant lastActiveAt;

    @Column(name = "deleted_at")
    private Instant deletedAt;

    /**
     * When the owner asked for the account to be deleted. Null means they have not, or they changed
     * their mind. The account stays usable until something outside this service completes the
     * deletion after the grace period in {@code docs/ACCOUNT.md}.
     */
    @Column(name = "deletion_requested_at")
    private Instant deletionRequestedAt;

    public boolean isLockedNow() {
        return lockedUntil != null && lockedUntil.isAfter(Instant.now());
    }

    /** False for magic-link / OTP / SSO-only accounts, which have never set a password. */
    public boolean hasPassword() {
        return passwordHash != null && !passwordHash.isBlank();
    }

    public boolean isEmailVerified() {
        return emailVerifiedAt != null;
    }

    /** What to greet them by: the short name if they set one, otherwise their full name. */
    public String effectiveDisplayName() {
        return displayName != null && !displayName.isBlank() ? displayName : fullName;
    }

    public enum UserStatus {
        ACTIVE, INVITED, DISABLED, LOCKED
    }
}
