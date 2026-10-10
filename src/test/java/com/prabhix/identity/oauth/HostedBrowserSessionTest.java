package com.prabhix.identity.oauth;

import com.prabhix.identity.common.Secrets;
import com.prabhix.identity.event.AuthEventRecorder;
import com.prabhix.identity.observability.AuthMetrics;
import com.prabhix.identity.risk.RiskEvaluator;
import com.prabhix.identity.security.TrustedClientIpResolver;
import com.prabhix.identity.session.DeviceSession;
import com.prabhix.identity.session.SessionCookieService;
import com.prabhix.identity.session.SessionService;
import com.prabhix.identity.session.SessionService.DeviceContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class HostedBrowserSessionTest {

    private static final String CURRENT_IP = "203.0.113.10";

    private SessionService sessions;
    private SessionCookieService cookies;
    private HostedBrowserSession browserSessions;

    @BeforeEach
    void setUp() {
        sessions = mock(SessionService.class);
        cookies = mock(SessionCookieService.class);
        TrustedClientIpResolver clientIp = mock(TrustedClientIpResolver.class);
        when(clientIp.resolve(any())).thenReturn(CURRENT_IP);
        RiskEvaluator risk = mock(RiskEvaluator.class);
        when(risk.newDevice()).thenReturn(RiskEvaluator.Decision.ALLOW);
        browserSessions = new HostedBrowserSession(
                sessions, cookies, clientIp, risk, mock(AuthMetrics.class), mock(AuthEventRecorder.class));
    }

    @Test
    @DisplayName("reauthentication rotates the cookie on the existing browser session")
    void reusesCurrentUsersSession() {
        UUID userId = UUID.randomUUID();
        DeviceSession existing = session(userId);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(cookies.read(request)).thenReturn(Optional.of("old-cookie"));
        when(sessions.findByCookie(Secrets.sha256("old-cookie"))).thenReturn(Optional.of(existing));
        when(sessions.recordAuthentication(existing.getId(), CURRENT_IP, true)).thenReturn(existing);

        UUID established = browserSessions.establish(userId, request, response, true);

        assertThat(established).isEqualTo(existing.getId());
        verify(sessions).recordAuthentication(existing.getId(), CURRENT_IP, true);
        verify(sessions, never()).touch(any());
        verify(cookies).issueRequired(response, existing.getId());
        verify(sessions, never()).openOrReuse(any(), any());
    }

    @Test
    @DisplayName("changing accounts revokes the previous browser session")
    void revokesPreviousAccountOnSharedBrowser() {
        UUID nextUser = UUID.randomUUID();
        DeviceSession previous = session(UUID.randomUUID());
        DeviceSession replacement = session(nextUser);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(cookies.read(request)).thenReturn(Optional.of("previous-cookie"));
        when(sessions.findByCookie(Secrets.sha256("previous-cookie"))).thenReturn(Optional.of(previous));
        when(sessions.openOrReuse(any(), any(DeviceContext.class))).thenReturn(replacement);
        when(sessions.recordAuthentication(replacement.getId(), CURRENT_IP, false)).thenReturn(replacement);

        UUID established = browserSessions.establish(nextUser, request, response, false);

        assertThat(established).isEqualTo(replacement.getId());
        verify(sessions).revoke(previous.getId(), "account_switched");
        verify(cookies).issueRequired(response, replacement.getId());
    }

    private static DeviceSession session(UUID userId) {
        DeviceSession session = new DeviceSession();
        session.setId(UUID.randomUUID());
        session.setUserId(userId);
        return session;
    }
}
