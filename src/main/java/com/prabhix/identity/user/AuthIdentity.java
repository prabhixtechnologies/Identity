package com.prabhix.identity.user;

import com.prabhix.identity.common.BaseEntity;
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

/** A federated login — a Google or Microsoft account — linked to an {@link IdentityUser}. */
@Getter
@Setter
@Entity
@Table(name = "auth_identities")
public class AuthIdentity extends BaseEntity {

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Enumerated(EnumType.STRING)
    @Column(name = "provider", nullable = false, length = 32)
    private AuthProvider provider;

    /**
     * The provider's own immutable id for the account, {@code sub} in an OIDC token.
     *
     * <p>Matched on rather than the email address, because a person can change the address on their
     * Google account and would otherwise arrive looking like a stranger.
     */
    @Column(name = "provider_subject", nullable = false, length = 255)
    private String providerSubject;

    @Column(name = "provider_email", columnDefinition = "citext")
    private String providerEmail;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "raw_profile", nullable = false, columnDefinition = "jsonb")
    private Map<String, Object> rawProfile = Map.of();

    @Column(name = "linked_at", nullable = false)
    private Instant linkedAt = Instant.now();

    @Column(name = "last_login_at")
    private Instant lastLoginAt;

    public enum AuthProvider {
        GOOGLE, MICROSOFT, GITHUB, SAML
    }
}
