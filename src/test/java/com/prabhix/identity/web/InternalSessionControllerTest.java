package com.prabhix.identity.web;

import com.prabhix.identity.event.AuthEventRecorder;
import com.prabhix.identity.event.AuthEventType;
import com.prabhix.identity.event.AuthEventType.Outcome;
import com.prabhix.identity.security.ServiceTokenAuthenticator;
import com.prabhix.identity.session.SessionService;
import com.prabhix.identity.session.SessionService.GlobalRevocationResult;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class InternalSessionControllerTest {

    private SessionService sessions;
    private ServiceTokenAuthenticator serviceTokens;
    private AuthEventRecorder events;
    private InternalSessionController controller;
    private HttpServletRequest request;

    @BeforeEach
    void setUp() {
        sessions = mock(SessionService.class);
        serviceTokens = mock(ServiceTokenAuthenticator.class);
        events = mock(AuthEventRecorder.class);
        controller = new InternalSessionController(sessions, serviceTokens, events);
        request = mock(HttpServletRequest.class);
    }

    @Test
    void revokeAllReturnsAggregateCounts() {
        when(sessions.revokeAllActiveGlobally("cutover", 200))
                .thenReturn(new GlobalRevocationResult(3, 5, 2));

        InternalSessionController.GlobalRevocationResponse response =
                controller.revokeAll(request, "cutover", null);

        assertThat(response.sessionsRevoked()).isEqualTo(3);
        assertThat(response.refreshTokensRevoked()).isEqualTo(5);
        assertThat(response.usersMarked()).isEqualTo(2);
        verify(serviceTokens).requireServiceToken(request);
        verify(events).record(eq(AuthEventType.ALL_SESSIONS_REVOKED), eq(Outcome.SUCCESS),
                eq(null), eq(null), any(), any());
    }

    @Test
    void revokeAllCapsBatchSize() {
        when(sessions.revokeAllActiveGlobally("cutover", 500))
                .thenReturn(new GlobalRevocationResult(0, 0, 0));

        controller.revokeAll(request, "cutover", 9999);

        verify(sessions).revokeAllActiveGlobally("cutover", 500);
    }
}
