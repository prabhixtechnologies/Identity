package com.prabhix.identity.webauthn;

import com.prabhix.identity.common.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * A passkey bound to an account.
 *
 * <p>The private key never leaves the authenticator; only the credential id and COSE public key are
 * stored here. {@code signatureCount} is updated on every successful assertion so a cloned
 * authenticator that replays an older counter is refused.
 */
@Getter
@Setter
@Entity
@Table(name = "webauthn_credentials")
public class WebAuthnCredential extends BaseEntity {

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(name = "credential_id", nullable = false, columnDefinition = "bytea")
    private byte[] credentialId;

    @Column(name = "public_key", nullable = false, columnDefinition = "bytea")
    private byte[] publicKey;

    @Column(name = "signature_count", nullable = false)
    private long signatureCount;

    @Column(name = "aaguid")
    private UUID aaguid;

    @Column(name = "label", length = 120)
    private String label;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "transports", nullable = false, columnDefinition = "jsonb")
    private List<String> transports = new ArrayList<>();

    /** Stamped on every successful assertion; null for a passkey that has never signed in. */
    @Column(name = "last_used_at")
    private Instant lastUsedAt;

    /**
     * The authenticator's backup-state flag at registration: whether the private key is synced to a
     * cloud keychain. Null for credentials registered before the column existed.
     */
    @Column(name = "backed_up")
    private Boolean backedUp;
}
