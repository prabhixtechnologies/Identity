package com.prabhix.identity.session;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface DeviceSessionRepository extends JpaRepository<DeviceSession, UUID> {

    Optional<DeviceSession> findByUserIdAndDeviceIdAndRevokedAtIsNull(UUID userId, String deviceId);

    Optional<DeviceSession> findByCookieTokenHash(String cookieTokenHash);

    List<DeviceSession> findByUserIdAndRevokedAtIsNullOrderByLastSeenAtDesc(UUID userId);
}
