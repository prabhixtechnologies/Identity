package com.prabhix.identity.event;

import com.prabhix.identity.common.Emails;
import com.prabhix.identity.event.AuthEventType.Outcome;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.PostLoad;
import jakarta.persistence.PostPersist;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import org.springframework.data.domain.Persistable;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * One row of the audit trail.
 *
 * <p>Not a {@code BaseEntity}: an event is written once and never updated, so a version column and
 * an {@code updated_at} would be a promise the table does not keep. The id is assigned here rather
 * than by the database so that {@link Persistable#isNew()} can say so and Spring Data persists rather
 * than merging — a merge is a SELECT before every INSERT, on the hottest write path in the service.
 */
@Getter
@Setter
@Entity
@Table(name = "auth_events")
public class AuthEventRecord implements Persistable<UUID> {

    @Id
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id = UUID.randomUUID();

    @Column(name = "user_id")
    private UUID userId;

    @Column(name = "email", columnDefinition = "citext")
    private String email;

    public void setEmail(String email) {
        this.email = Emails.normalize(email);
    }

    @Enumerated(EnumType.STRING)
    @Column(name = "type", nullable = false, columnDefinition = "text")
    private AuthEventType type;

    @Enumerated(EnumType.STRING)
    @Column(name = "outcome", nullable = false, columnDefinition = "text")
    private Outcome outcome;

    @Column(name = "client_id", columnDefinition = "text")
    private String clientId;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "user_agent", length = 500)
    private String userAgent;

    @Column(name = "actor_user_id")
    private UUID actorUserId;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "details", nullable = false, columnDefinition = "jsonb")
    private Map<String, Object> details = new LinkedHashMap<>();

    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt = Instant.now();

    @Transient
    private boolean persisted;

    @Override
    public boolean isNew() {
        return !persisted;
    }

    @PostPersist
    @PostLoad
    void markPersisted() {
        persisted = true;
    }
}
