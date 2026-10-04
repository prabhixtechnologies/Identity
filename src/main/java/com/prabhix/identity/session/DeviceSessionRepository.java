package com.prabhix.identity.session;

import jakarta.persistence.LockModeType;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface DeviceSessionRepository extends JpaRepository<DeviceSession, UUID> {

    Optional<DeviceSession> findByUserIdAndDeviceIdAndRevokedAtIsNull(UUID userId, String deviceId);

    Optional<DeviceSession> findByCookieTokenHash(String cookieTokenHash);

    @Query("""
            select session from DeviceSession session
             where session.cookieTokenHash = :hash
                or (session.cookiePreviousHash = :hash
                    and session.cookiePreviousExpiresAt > :now)
            """)
    Optional<DeviceSession> findByPresentedCookie(@Param("hash") String hash, @Param("now") Instant now);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select session from DeviceSession session where session.id = :id")
    Optional<DeviceSession> lockById(@Param("id") UUID id);

    List<DeviceSession> findByUserIdAndRevokedAtIsNullOrderByLastSeenAtDesc(UUID userId);

    @Query("""
            select session from DeviceSession session
             where session.revokedAt is null
             order by session.createdAt
            """)
    List<DeviceSession> findActiveSessions(Pageable pageable);
}
