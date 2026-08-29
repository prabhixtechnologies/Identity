package com.prabhix.identity.session;

import com.prabhix.identity.common.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

/** One signed-in device or browser. The {@code sid} claim names a row in this table. */
@Getter
@Setter
@Entity
@Table(name = "device_sessions")
public class DeviceSession extends BaseEntity {

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(name = "device_id", length = 128)
    private String deviceId;

    @Column(name = "device_name", length = 160)
    private String deviceName;

    @Enumerated(EnumType.STRING)
    @Column(name = "device_type", nullable = false, length = 24)
    private DeviceType deviceType = DeviceType.WEB;

    @Column(name = "user_agent", length = 500)
    private String userAgent;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "last_seen_at", nullable = false)
    private Instant lastSeenAt = Instant.now();

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "revoked_reason", length = 64)
    private String revokedReason;

    /**
     * SHA-256 of the shared browser session cookie, or null for a session that has none — every
     * phone and any web session created before the cookie existed.
     *
     * <p>Unlike a refresh token this does not rotate, which is the entire point: two console
     * hostnames exchanging it at the same moment must both succeed, where rotation would treat the
     * second as a replay and revoke the session.
     */
    @Column(name = "cookie_token_hash", length = 64)
    private String cookieTokenHash;

    @Column(name = "cookie_expires_at")
    private Instant cookieExpiresAt;

    public boolean isActive() {
        return revokedAt == null;
    }

    /** True when the cookie on this session is still usable to mint an access token. */
    public boolean hasUsableCookie(Instant now) {
        return isActive()
                && cookieTokenHash != null
                && cookieExpiresAt != null
                && cookieExpiresAt.isAfter(now);
    }

    public void revoke(String reason) {
        revokedAt = Instant.now();
        revokedReason = reason;
        // Cleared as well as revoked. The revocation alone is enough to refuse the exchange, but
        // dropping the hash means the cookie the browser may still hold matches no row at all.
        cookieTokenHash = null;
        cookieExpiresAt = null;
    }

    public enum DeviceType {
        WEB, IOS, ANDROID, API
    }
}
