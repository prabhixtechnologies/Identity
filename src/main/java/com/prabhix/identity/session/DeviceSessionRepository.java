package com.prabhix.identity.session;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface DeviceSessionRepository extends JpaRepository<DeviceSession, UUID> {

    Optional<DeviceSession> findByUserIdAndDeviceIdAndRevokedAtIsNull(UUID userId, String deviceId);

    Optional<DeviceSession> findByCookieTokenHash(String cookieTokenHash);

    List<DeviceSession> findByUserIdAndRevokedAtIsNullOrderByLastSeenAtDesc(UUID userId);

    @Query("""
            select session from DeviceSession session
             where session.revokedAt is null
             order by session.createdAt
            """)
    List<DeviceSession> findActiveSessions(Pageable pageable);
}
