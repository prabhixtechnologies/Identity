package com.prabhix.identity.security.internal;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.config.TestProperties;
import com.prabhix.identity.event.AuthEventRecorder;
import com.prabhix.identity.event.AuthEventType;
import com.prabhix.identity.security.ServiceTokenAuthenticator;
import com.prabhix.identity.security.TrustedClientIpResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class InternalServiceAuthValidatorTest {

    private static final String TOKEN = "test-service-token";

    private InternalFailedAuthRateLimiter failureLimiter;
    private AuthEventRecorder events;
    private InternalServiceAuthValidator validator;

    @BeforeEach
    void setUp() {
        failureLimiter = mock(InternalFailedAuthRateLimiter.class);
        events = mock(AuthEventRecorder.class);
        var properties = TestProperties.signing("", List.of());
        validator = new InternalServiceAuthValidator(
                properties,
                failureLimiter,
                events,
                new TrustedClientIpResolver(properties));
    }

    @Test
    void rejectsMissingServiceTokenWithAudit() {
        MockHttpServletRequest request = post("/internal/identity/users/lookup");

        assertThatThrownBy(() -> validator.verify(request, true))
                .isInstanceOf(ApiException.class)
                .extracting(ex -> ((ApiException) ex).getCode())
                .isEqualTo(ErrorCode.UNAUTHENTICATED);

        verify(failureLimiter).recordFailure(any(), eq(null));
        verify(events).failure(eq(AuthEventType.INTERNAL_ACCESS_DENIED), eq(null), eq(null), any());
    }

    @Test
    void acceptsAutomatedRouteWithValidToken() {
        MockHttpServletRequest request = post("/internal/identity/users/lookup");
        request.addHeader(ServiceTokenAuthenticator.SERVICE_TOKEN_HEADER, TOKEN);

        validator.verify(request, true);

        assertThat(request.getAttribute(InternalServiceAuthValidator.VERIFIED_REQUEST_ATTRIBUTE))
                .isEqualTo(Boolean.TRUE);
        verify(failureLimiter, never()).recordFailure(any(), any());
    }

    @Test
    void adminRouteRequiresActingUser() {
        MockHttpServletRequest request = post("/internal/identity/admin/users/disable");
        request.addHeader(ServiceTokenAuthenticator.SERVICE_TOKEN_HEADER, TOKEN);

        assertThatThrownBy(() -> validator.verify(request, true))
                .isInstanceOf(ApiException.class)
                .extracting(ex -> ((ApiException) ex).getCode())
                .isEqualTo(ErrorCode.ACTING_USER_REQUIRED);
    }

    @Test
    void adminRouteAcceptsValidActingUser() {
        MockHttpServletRequest request = post("/internal/identity/admin/users/disable");
        request.addHeader(ServiceTokenAuthenticator.SERVICE_TOKEN_HEADER, TOKEN);
        request.addHeader(ServiceTokenAuthenticator.ACTING_USER_HEADER, UUID.randomUUID().toString());

        validator.verify(request, true);

        assertThat(request.getAttribute(InternalServiceAuthValidator.VERIFIED_REQUEST_ATTRIBUTE))
                .isEqualTo(Boolean.TRUE);
    }

    @Test
    void secondVerifySkipsWhenAttributeSet() {
        MockHttpServletRequest request = post("/internal/identity/users/lookup");
        request.addHeader(ServiceTokenAuthenticator.SERVICE_TOKEN_HEADER, TOKEN);
        request.setAttribute(InternalServiceAuthValidator.VERIFIED_REQUEST_ATTRIBUTE, Boolean.TRUE);

        validator.verify(request, true);

        verify(failureLimiter, never()).recordFailure(any(), any());
    }

    @Test
    void failsClosedWhenServiceTokenNotConfigured() {
        var properties = TestProperties.forIssuer("https://id.example.com", "", List.of());
        var unconfigured = new InternalServiceAuthValidator(
                new com.prabhix.identity.config.IdentityProperties(
                        properties.issuer(),
                        properties.token(),
                        properties.signing(),
                        properties.password(),
                        properties.lockout(),
                        properties.challenge(),
                        properties.sessionCookie(),
                        properties.urls(),
                        properties.sso(),
                        properties.sms(),
                        properties.whatsApp(),
                        properties.webAuthn(),
                        properties.mail(),
                        properties.clients(),
                        properties.platform(),
                        "",
                        properties.rateLimit(),
                        properties.trustedProxy()),
                failureLimiter,
                events,
                new TrustedClientIpResolver(properties));
        MockHttpServletRequest request = post("/internal/identity/users/lookup");
        request.addHeader(ServiceTokenAuthenticator.SERVICE_TOKEN_HEADER, "anything");

        assertThatThrownBy(() -> unconfigured.verify(request, true))
                .extracting(ex -> ((ApiException) ex).getCode())
                .isEqualTo(ErrorCode.FEATURE_DISABLED);
    }

    private static MockHttpServletRequest post(String path) {
        return new MockHttpServletRequest("POST", path);
    }
}
