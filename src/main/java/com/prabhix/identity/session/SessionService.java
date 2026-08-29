package com.prabhix.identity.session;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.common.Secrets;
import com.prabhix.identity.config.IdentityProperties;
import com.prabhix.identity.session.DeviceSession.DeviceType;
import com.prabhix.identity.token.TokenDenyList;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** Device sessions and the rotating refresh tokens attached to them. */
@Slf4j
@Service
@RequiredArgsConstructor
public class SessionService {

    private static final int USER_AGENT_MAX = 500;

    private final DeviceSessionRepository sessions;
    private final RefreshTokenRepository refreshTokens;
    private final TokenDenyList denyList;
    private final IdentityProperties properties;

    /**
     * Finds the live session for a device, or opens one.
     *
     * <p>Reusing a session for a known {@code deviceId} is what stops a phone that reinstalls its
     * token from accumulating a row per sign-in, which would make "sign out my other devices" show a
     * list nobody could interpret. Clients that send no device id always get a new row, because
     * there is nothing to recognise them by.
     */
    @Transactional
    public DeviceSession openOrReuse(UUID userId, DeviceContext device) {
        if (device.deviceId() != null && !device.deviceId().isBlank()) {
            Optional<DeviceSession> existing =
                    sessions.findByUserIdAndDeviceIdAndRevokedAtIsNull(userId, device.deviceId());
            if (existing.isPresent()) {
                DeviceSession session = existing.get();
                session.setLastSeenAt(Instant.now());
                if (device.deviceName() != null && !device.deviceName().isBlank()) {
                    session.setDeviceName(device.deviceName());
                }
                if (device.userAgent() != null) {
                    session.setUserAgent(truncate(device.userAgent()));
                }
                if (device.ipAddress() != null) {
                    session.setIpAddress(device.ipAddress());
                }
                return sessions.save(session);
            }
        }

        DeviceSession session = new DeviceSession();
        session.setUserId(userId);
        session.setDeviceId(device.deviceId());
        session.setDeviceName(device.deviceName());
        session.setDeviceType(device.deviceType());
        session.setUserAgent(truncate(device.userAgent()));
        session.setIpAddress(device.ipAddress());
        session.setLastSeenAt(Instant.now());
        return sessions.save(session);
    }

    @Transactional
    public DeviceSession touch(UUID sessionId) {
        DeviceSession session = sessions.findById(sessionId)
                .orElseThrow(() -> ApiException.of(ErrorCode.TOKEN_INVALID, "That session no longer exists"));
        if (!session.isActive()) {
            throw ApiException.of(ErrorCode.TOKEN_REVOKED, "This session was signed out");
        }
        session.setLastSeenAt(Instant.now());
        return sessions.save(session);
    }

    @Transactional(readOnly = true)
    public Optional<DeviceSession> findByCookie(String cookieTokenHash) {
        return sessions.findByCookieTokenHash(cookieTokenHash);
    }

    @Transactional
    public void bindCookie(UUID sessionId, String cookieTokenHash, Instant expiresAt) {
        sessions.findById(sessionId)
                .filter(DeviceSession::isActive)
                .ifPresent(session -> {
                    session.setCookieTokenHash(cookieTokenHash);
                    session.setCookieExpiresAt(expiresAt);
                    sessions.save(session);
                });
    }

    @Transactional(readOnly = true)
    public List<DeviceSession> listActive(UUID userId) {
        return sessions.findByUserIdAndRevokedAtIsNullOrderByLastSeenAtDesc(userId);
    }

    /** @return the raw token, which is not recoverable afterwards — only its hash is stored */
    @Transactional
    public String issueRefreshToken(UUID userId, UUID sessionId) {
        return mint(userId, sessionId).raw();
    }

    private MintedToken mint(UUID userId, UUID sessionId) {
        String raw = Secrets.token();
        RefreshToken token = new RefreshToken();
        token.setUserId(userId);
        token.setSessionId(sessionId);
        token.setTokenHash(Secrets.sha256(raw));
        token.setExpiresAt(Instant.now().plus(properties.token().refreshTokenTtl()));
        return new MintedToken(refreshTokens.save(token), raw);
    }

    private record MintedToken(RefreshToken entity, String raw) {
    }

    /**
     * Consumes a refresh token and hands out its successor.
     *
     * @return the session the token belonged to, plus the replacement token
     * @throws ApiException with {@code TOKEN_REVOKED} when the token was already used, which is
     *     replay — see {@link #handleReplay}
     */
    @Transactional
    public RotatedToken rotate(String rawRefreshToken) {
        RefreshToken token = refreshTokens.findByTokenHash(Secrets.sha256(rawRefreshToken))
                .orElseThrow(() -> ApiException.of(ErrorCode.TOKEN_INVALID, "That refresh token is not valid"));

        if (token.getUsedAt() != null) {
            handleReplay(token);
            throw ApiException.of(ErrorCode.TOKEN_REVOKED,
                    "This session was revoked because a refresh token was reused");
        }
        if (token.getRevokedAt() != null || token.getExpiresAt().isBefore(Instant.now())) {
            throw ApiException.of(ErrorCode.TOKEN_INVALID, "That refresh token is not valid");
        }

        token.setUsedAt(Instant.now());
        refreshTokens.save(token);

        DeviceSession session = touch(token.getSessionId());

        // The link back from consumed token to successor is what makes the whole family reachable
        // when a replay is detected later, so it is written now rather than inferred.
        MintedToken successor = mint(token.getUserId(), session.getId());
        token.setReplacedBy(successor.entity().getId());
        refreshTokens.save(token);

        return new RotatedToken(session, token.getUserId(), successor.raw());
    }

    /**
     * A replayed refresh token is either a genuine attacker holding a stolen one or a client that
     * raced itself into sending the same token twice. Both are answered by revoking the affected
     * token family and the one session it belongs to.
     *
     * <p>This deliberately leaves the user's other devices signed in. Revoking everything used to
     * mean a race in one browser tab also signed the user out on their phone, and it handed anyone
     * able to replay a single token a cheap way to lock the real owner out of every device at once.
     * Confining the damage to the compromised family is what RFC 9700 asks for.
     */
    private void handleReplay(RefreshToken reused) {
        revokeChain(reused.getId());
        revoke(reused.getSessionId(), "token_theft");
        log.warn("Refresh token replay on session {} for user {}; family and session revoked",
                reused.getSessionId(), reused.getUserId());
    }

    private void revokeChain(UUID tokenId) {
        refreshTokens.findById(tokenId).ifPresent(token -> {
            token.setRevokedAt(Instant.now());
            refreshTokens.save(token);
            if (token.getReplacedBy() != null) {
                revokeChain(token.getReplacedBy());
            }
        });
    }

    @Transactional
    public void revoke(UUID sessionId, String reason) {
        if (sessionId == null) {
            return;
        }
        sessions.findById(sessionId).ifPresent(session -> {
            if (session.getRevokedAt() == null) {
                session.revoke(reason);
                sessions.save(session);
            }
        });
        // Unconditional, and after the row update: access tokens already minted for this session
        // stay valid until they expire unless the deny list is told about it.
        denyList.revokeSession(sessionId);
    }

    /**
     * Revokes one session on the user's own instruction, e.g. "sign out my old phone".
     *
     * @throws ApiException with {@code NOT_FOUND} when the session belongs to somebody else, rather
     *     than {@code FORBIDDEN}, so that the endpoint cannot be used to discover session ids
     */
    @Transactional
    public void revokeOwn(UUID userId, UUID sessionId) {
        DeviceSession session = sessions.findById(sessionId)
                .filter(candidate -> candidate.getUserId().equals(userId))
                .orElseThrow(() -> ApiException.notFound("That session"));
        revoke(session.getId(), "user_revoked");
    }

    @Transactional
    public void revokeRefreshToken(String rawRefreshToken) {
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            return;
        }
        refreshTokens.findByTokenHash(Secrets.sha256(rawRefreshToken)).ifPresent(token -> {
            token.setRevokedAt(Instant.now());
            refreshTokens.save(token);
        });
    }

    private String truncate(String value) {
        if (value == null) {
            return null;
        }
        return value.length() <= USER_AGENT_MAX ? value : value.substring(0, USER_AGENT_MAX);
    }

    /** What the transport layer knows about the caller's device. */
    public record DeviceContext(
            String deviceId,
            String deviceName,
            DeviceType deviceType,
            String userAgent,
            String ipAddress) {

        public static DeviceContext of(String deviceId,
                                       String deviceName,
                                       String deviceType,
                                       String userAgent,
                                       String ipAddress) {
            return new DeviceContext(deviceId, deviceName, parseType(deviceType), userAgent, ipAddress);
        }

        /**
         * Unknown values fall back to WEB rather than throwing. A client sending a device type this
         * build has not heard of is not a reason to refuse a sign-in.
         */
        private static DeviceType parseType(String value) {
            if (value == null || value.isBlank()) {
                return DeviceType.WEB;
            }
            try {
                return DeviceType.valueOf(value.trim().toUpperCase());
            } catch (IllegalArgumentException ex) {
                return DeviceType.WEB;
            }
        }
    }

    public record RotatedToken(DeviceSession session, UUID userId, String refreshToken) {
    }
}
