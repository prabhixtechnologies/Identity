package com.prabhix.identity.common;

import jakarta.persistence.Column;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.Version;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.UuidGenerator;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Identity, optimistic locking and who/when provenance for every entity here.
 *
 * <p>The platform splits this across {@code BaseEntity} and {@code AuditableEntity}. Every table in
 * this service is audited, so the split would buy nothing but a second file.
 *
 * <p>Equality is by primary key only, and an unpersisted entity equals nothing but itself. Lombok's
 * generated equals would break Hibernate collections, because the field values it hashes change as
 * the entity is loaded and mutated.
 */
@Getter
@Setter
@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
public abstract class BaseEntity {

    @Id
    @GeneratedValue
    @UuidGenerator
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @Version
    @Column(name = "version", nullable = false)
    private long version;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @CreatedBy
    @Column(name = "created_by", updatable = false)
    private UUID createdBy;

    @LastModifiedBy
    @Column(name = "updated_by")
    private UUID updatedBy;

    @Override
    public final boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof BaseEntity that)) {
            return false;
        }
        // Hibernate proxies subclass the entity, so compare on the persistent class.
        if (!getClass().isInstance(other) && !other.getClass().isInstance(this)) {
            return false;
        }
        return id != null && Objects.equals(id, that.getId());
    }

    @Override
    public final int hashCode() {
        return id != null ? id.hashCode() : System.identityHashCode(this);
    }
}
