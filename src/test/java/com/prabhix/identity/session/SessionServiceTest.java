package com.prabhix.identity.session;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.common.Secrets;
import com.prabhix.identity.config.TestProperties;
import com.prabhix.identity.session.DeviceSession.DeviceType;
import com.prabhix.identity.session.SessionService.DeviceContext;
import com.prabhix.identity.session.SessionService.RotatedToken;
import com.prabhix.identity.token.TokenDenyList;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SessionServiceTest {

    private final Map<UUID, DeviceSession> sessionRows = new HashMap<>();
    private final Map<UUID, RefreshToken> tokenRows = new HashMap<>();

    private DeviceSessionRepository sessions;
    private RefreshTokenRepository refreshTokens;
    private TokenDenyList denyList;
    private SessionService service;

    @BeforeEach
    void setUp() {
        sessions = mock(DeviceSessionRepository.class);
        refreshTokens = mock(RefreshTokenRepository.class);
        denyList = mock(TokenDenyList.class);
        service = new SessionService(sessions, refreshTokens, denyList,
                TestProperties.signing("", List.of()));

        // Stand-in stores rather than per-test stubs. Rotation and replay are about how several rows
        // relate to each other, and stubbing each lookup individually describes the assertions twice.
        when(sessions.save(any(DeviceSession.class))).thenAnswer(call -> {
            DeviceSession session = call.getArgument(0);
            if (session.getId() == null) {
                session.setId(UUID.randomUUID());
            }
            sessionRows.put(session.getId(), session);
            return session;
        });
        when(sessions.findById(any())).thenAnswer(call ->
                Optional.ofNullable(sessionRows.get(call.<UUID>getArgument(0))));
        when(refreshTokens.save(any(RefreshToken.class))).thenAnswer(call -> {
            RefreshToken token = call.getArgument(0);
            if (token.getId() == null) {
                token.setId(UUID.randomUUID());
            }
            tokenRows.put(token.getId(), token);
            return token;
        });
        when(refreshTokens.findById(any())).thenAnswer(call ->
                Optional.ofNullable(tokenRows.get(call.<UUID>getArgument(0))));
        when(refreshTokens.findByTokenHash(any())).thenAnswer(call -> {
            String hash = call.getArgument(0);
            return tokenRows.values().stream()
                    .filter(token -> hash.equals(token.getTokenHash()))
                    .findFirst();
        });
    }

    private DeviceContext web() {
        return new DeviceContext(null, "Chrome on Windows", DeviceType.WEB, "Mozilla/5.0", "1.2.3.4");
    }

    @Test
    @DisplayName("only the hash of a refresh token is stored")
    void storesOnlyTheHash() {
        DeviceSession session = service.openOrReuse(UUID.randomUUID(), web());

        String raw = service.issueRefreshToken(session.getUserId(), session.getId());

        assertThat(tokenRows.values()).allSatisfy(token -> {
            assertThat(token.getTokenHash()).isNotEqualTo(raw);
            assertThat(token.getTokenHash()).isEqualTo(Secrets.sha256(raw));
        });
    }

    @Test
    @DisplayName("rotation consumes the presented token and links it to its successor")
    void rotationLinksTheChain() {
        UUID userId = UUID.randomUUID();
        DeviceSession session = service.openOrReuse(userId, web());
        String first = service.issueRefreshToken(userId, session.getId());

        RotatedToken rotated = service.rotate(first);

        RefreshToken consumed = tokenRows.values().stream()
                .filter(token -> token.getTokenHash().equals(Secrets.sha256(first)))
                .findFirst().orElseThrow();
        assertThat(consumed.getUsedAt()).isNotNull();
        // The link is what makes the whole family reachable when a replay shows up later.
        assertThat(consumed.getReplacedBy()).isNotNull();
        assertThat(rotated.refreshToken()).isNotEqualTo(first);
        assertThat(rotated.session().getId()).isEqualTo(session.getId());
    }

    @Test
    @DisplayName("replaying a consumed token revokes the family and the session it belongs to")
    void replayRevokesTheFamily() {
        UUID userId = UUID.randomUUID();
        DeviceSession session = service.openOrReuse(userId, web());
        String first = service.issueRefreshToken(userId, session.getId());
        String second = service.rotate(first).refreshToken();

        assertThatThrownBy(() -> service.rotate(first))
                .isInstanceOf(ApiException.class)
                .satisfies(thrown ->
                        assertThat(((ApiException) thrown).getCode()).isEqualTo(ErrorCode.TOKEN_REVOKED));

        // Both the replayed token and the successor it had already produced: whoever replayed the
        // first one may be holding the second, so revoking only the presented token achieves nothing.
        assertThat(tokenRows.values()).allSatisfy(token ->
                assertThat(token.getRevokedAt()).isNotNull());
        assertThat(sessionRows.get(session.getId()).getRevokedAt()).isNotNull();
        assertThat(sessionRows.get(session.getId()).getRevokedReason()).isEqualTo("token_theft");
        verify(denyList).revokeSession(session.getId());
        // And the successor is now useless too, which is the point.
        assertThatThrownBy(() -> service.rotate(second)).isInstanceOf(ApiException.class);
    }

    @Test
    @DisplayName("a replay on one device leaves the user's other sessions alone")
    void replayDoesNotSignOutOtherDevices() {
        UUID userId = UUID.randomUUID();
        DeviceSession laptop = service.openOrReuse(userId,
                new DeviceContext("laptop", "Laptop", DeviceType.WEB, null, null));
        DeviceSession phone = service.openOrReuse(userId,
                new DeviceContext("phone", "Phone", DeviceType.ANDROID, null, null));
        String laptopToken = service.issueRefreshToken(userId, laptop.getId());
        String phoneToken = service.issueRefreshToken(userId, phone.getId());
        service.rotate(laptopToken);

        assertThatThrownBy(() -> service.rotate(laptopToken)).isInstanceOf(ApiException.class);

        // Revoking everything used to mean a race in one browser tab signed the user out on their
        // phone, and handed anyone who could replay one token a way to lock the owner out everywhere.
        assertThat(sessionRows.get(phone.getId()).getRevokedAt()).isNull();
        assertThat(service.rotate(phoneToken)).isNotNull();
    }

    @Test
    @DisplayName("an expired refresh token is invalid rather than treated as theft")
    void expiredTokenIsNotTheft() {
        UUID userId = UUID.randomUUID();
        DeviceSession session = service.openOrReuse(userId, web());
        String raw = service.issueRefreshToken(userId, session.getId());
        tokenRows.values().forEach(token -> token.setExpiresAt(Instant.now().minusSeconds(1)));

        assertThatThrownBy(() -> service.rotate(raw))
                .isInstanceOf(ApiException.class)
                .satisfies(thrown ->
                        assertThat(((ApiException) thrown).getCode()).isEqualTo(ErrorCode.TOKEN_INVALID));

        // Expiry is the passage of time, not an attack, so the session survives and the user simply
        // signs in again.
        assertThat(sessionRows.get(session.getId()).getRevokedAt()).isNull();
    }

    @Test
    @DisplayName("a known device reuses its session instead of accumulating rows")
    void reusesSessionForKnownDevice() {
        UUID userId = UUID.randomUUID();
        DeviceContext phone = new DeviceContext("phone-1", "Phone", DeviceType.ANDROID, null, "1.1.1.1");
        DeviceSession first = service.openOrReuse(userId, phone);
        when(sessions.findByUserIdAndDeviceIdAndRevokedAtIsNull(userId, "phone-1"))
                .thenReturn(Optional.of(first));

        DeviceSession second = service.openOrReuse(userId,
                new DeviceContext("phone-1", "Phone 15", DeviceType.ANDROID, null, "5.5.5.5"));

        assertThat(second.getId()).isEqualTo(first.getId());
        assertThat(second.getDeviceName()).isEqualTo("Phone 15");
        assertThat(second.getIpAddress()).isEqualTo("5.5.5.5");
    }

    @Test
    @DisplayName("a client that sends no device id always gets a new session")
    void anonymousDeviceGetsItsOwnSession() {
        UUID userId = UUID.randomUUID();

        DeviceSession first = service.openOrReuse(userId, web());
        DeviceSession second = service.openOrReuse(userId, web());

        // There is nothing to recognise such a client by, and guessing would merge two people
        // sharing a machine into one session.
        assertThat(second.getId()).isNotEqualTo(first.getId());
    }

    @Test
    @DisplayName("revoking clears the session cookie hash as well as the row")
    void revokeClearsTheCookie() {
        DeviceSession session = service.openOrReuse(UUID.randomUUID(), web());
        service.bindCookie(session.getId(), Secrets.sha256("cookie-value"),
                Instant.now().plusSeconds(3600));

        service.revoke(session.getId(), "logout");

        // Revocation alone would refuse the exchange, but dropping the hash means the value the
        // browser may still be holding corresponds to no row at all.
        assertThat(sessionRows.get(session.getId()).getCookieTokenHash()).isNull();
        assertThat(sessionRows.get(session.getId()).getCookieExpiresAt()).isNull();
    }

    @Test
    @DisplayName("revoking somebody else's session reads as not found, not forbidden")
    void cannotRevokeAnotherUsersSession() {
        DeviceSession theirs = service.openOrReuse(UUID.randomUUID(), web());

        assertThatThrownBy(() -> service.revokeOwn(UUID.randomUUID(), theirs.getId()))
                .isInstanceOf(ApiException.class)
                .satisfies(thrown ->
                        assertThat(((ApiException) thrown).getCode()).isEqualTo(ErrorCode.NOT_FOUND));

        // A 403 would confirm the id names a real session, turning the endpoint into a way to
        // enumerate them.
        assertThat(sessionRows.get(theirs.getId()).getRevokedAt()).isNull();
    }

    @Test
    @DisplayName("rotating against a revoked session is refused")
    void revokedSessionCannotRefresh() {
        UUID userId = UUID.randomUUID();
        DeviceSession session = service.openOrReuse(userId, web());
        String raw = service.issueRefreshToken(userId, session.getId());
        service.revoke(session.getId(), "logout");

        assertThatThrownBy(() -> service.rotate(raw))
                .isInstanceOf(ApiException.class)
                .satisfies(thrown ->
                        assertThat(((ApiException) thrown).getCode()).isEqualTo(ErrorCode.TOKEN_REVOKED));
    }
}
