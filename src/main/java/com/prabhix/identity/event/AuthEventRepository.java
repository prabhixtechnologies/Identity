package com.prabhix.identity.event;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

/**
 * Writes, and the one read the admin detail page needs. Paged searches over the table go through
 * {@link AuthEventQueries}, because a keyset cursor with optional filters does not fit a derived
 * query.
 */
public interface AuthEventRepository extends JpaRepository<AuthEventRecord, UUID> {

    List<AuthEventRecord> findTop20ByUserIdOrderByOccurredAtDesc(UUID userId);

    List<AuthEventRecord> findByUserIdAndTypeOrderByOccurredAtDesc(UUID userId, AuthEventType type);
}
