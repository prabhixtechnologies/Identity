package com.prabhix.identity.session;

import com.prabhix.identity.common.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

/**
 * A single-use, rotating refresh token.
 *
 * <p>Only the SHA-256 of the value is stored, so a database leak does not hand anyone a working
 * credential. Rotation is what makes replay detectable: once {@link #usedAt} is set, a second
 * presentation of the same value means either theft or a client racing itself.
 */
@Getter
@Setter
@Entity
@Table(name = "refresh_tokens")
public class RefreshToken extends BaseEntity {

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(name = "session_id", nullable = false)
    private UUID sessionId;

    @Column(name = "token_hash", nullable = false, length = 64, unique = true)
    private String tokenHash;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "used_at")
    private Instant usedAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    /** The token issued in exchange for this one. Following it revokes the whole family. */
    @Column(name = "replaced_by")
    private UUID replacedBy;

    public boolean isUsable() {
        return usedAt == null && revokedAt == null && expiresAt.isAfter(Instant.now());
    }
}
