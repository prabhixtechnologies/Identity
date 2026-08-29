package com.prabhix.identity.challenge;

import com.prabhix.identity.common.BaseEntity;
import com.prabhix.identity.common.Emails;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * A one-time secret sent to an address: magic link, OTP, password reset, email verification.
 *
 * <p>Only the hash is stored, so the row is worthless to anyone who reads the table. Attempts are
 * counted per row rather than per address so that a six-digit OTP cannot be brute-forced — a
 * million guesses against a rate limiter would otherwise be a matter of patience.
 */
@Getter
@Setter
@Entity
@Table(name = "auth_challenges")
public class AuthChallenge extends BaseEntity {

    @Enumerated(EnumType.STRING)
    @Column(name = "purpose", nullable = false, length = 32)
    private ChallengePurpose purpose;

    @Column(name = "user_id")
    private UUID userId;

    @Column(name = "destination", nullable = false, columnDefinition = "citext")
    private String destination;

    /**
     * Normalizes, so requesting an OTP for {@code Owner@x.com} and verifying it as {@code owner@x.com}
     * finds the same row. Harmless for the SMS and WhatsApp purposes, where the destination is digits
     * and a plus sign. See {@link Emails}.
     */
    public void setDestination(String destination) {
        this.destination = Emails.normalize(destination);
    }

    @Column(name = "secret_hash", nullable = false, length = 64)
    private String secretHash;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "consumed_at")
    private Instant consumedAt;

    @Column(name = "attempts", nullable = false)
    private int attempts;

    @Column(name = "max_attempts", nullable = false)
    private int maxAttempts;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "metadata", nullable = false, columnDefinition = "jsonb")
    private Map<String, Object> metadata = Map.of();

    public boolean isExpired() {
        return expiresAt.isBefore(Instant.now());
    }

    public boolean isConsumed() {
        return consumedAt != null;
    }

    public boolean isOutOfAttempts() {
        return attempts >= maxAttempts;
    }

    public enum ChallengePurpose {
        MAGIC_LINK, EMAIL_OTP, SMS_OTP, WHATSAPP_OTP, PASSWORD_RESET, EMAIL_VERIFY
    }
}
