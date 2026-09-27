package com.prabhix.identity.security.internal;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.common.Secrets;
import com.prabhix.identity.config.IdentityProperties;
import com.prabhix.identity.event.AuthEventRecorder;
import com.prabhix.identity.event.AuthEventType;
import com.prabhix.identity.security.RequestMetadata;
import com.prabhix.identity.security.ServiceTokenAuthenticator;
import com.prabhix.identity.security.TrustedClientIpResolver;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.UUID;

import static com.prabhix.identity.event.AuthEventRecorder.details;

/**
 * Shared gate for {@code /internal}: configured token, constant-time compare, failure throttling,
 * and acting-user rules. Controllers keep their existing checks as defence in depth.
 */
@Component
@RequiredArgsConstructor
public class InternalServiceAuthValidator {

    /** Set when this request already passed {@link InternalServiceAuthFilter}. */
    public static final String VERIFIED_REQUEST_ATTRIBUTE =
            "com.prabhix.identity.internal.serviceAuthVerified";

    private final IdentityProperties properties;
    private final InternalFailedAuthRateLimiter failureLimiter;
    private final AuthEventRecorder events;
    private final TrustedClientIpResolver clientIp;

    public void verify(HttpServletRequest request, boolean recordFailures) {
        if (Boolean.TRUE.equals(request.getAttribute(VERIFIED_REQUEST_ATTRIBUTE))) {
            return;
        }
        String expected = properties.serviceToken();
        if (expected == null || expected.isBlank()) {
            throw ApiException.of(ErrorCode.FEATURE_DISABLED,
                    "This deployment has no service token configured");
        }

        String presented = request.getHeader(ServiceTokenAuthenticator.SERVICE_TOKEN_HEADER);
        if (presented == null || !Secrets.constantTimeEquals(expected, presented)) {
            if (recordFailures) {
                onFailure(request, presented, "invalid_service_token");
            }
            throw ApiException.of(ErrorCode.UNAUTHENTICATED, "That service token is not valid");
        }

        if (InternalRoutePolicy.requiresActingUser(request)
                && !InternalRoutePolicy.isAutomatedServiceRoute(request)) {
            requireActingUserHeader(request, recordFailures);
        }

        request.setAttribute(VERIFIED_REQUEST_ATTRIBUTE, Boolean.TRUE);
    }

    private void requireActingUserHeader(HttpServletRequest request, boolean recordFailures) {
        String header = request.getHeader(ServiceTokenAuthenticator.ACTING_USER_HEADER);
        if (header == null || header.isBlank()) {
            if (recordFailures) {
                onFailure(request, null, "acting_user_required");
            }
            throw ApiException.of(ErrorCode.ACTING_USER_REQUIRED,
                    ServiceTokenAuthenticator.ACTING_USER_HEADER
                            + " must carry the id of the staff member making this request");
        }
        try {
            UUID.fromString(header.trim());
        } catch (IllegalArgumentException ex) {
            if (recordFailures) {
                onFailure(request, null, "acting_user_invalid");
            }
            throw ApiException.of(ErrorCode.ACTING_USER_REQUIRED,
                    ServiceTokenAuthenticator.ACTING_USER_HEADER
                            + " must carry the id of the staff member making this request");
        }
    }

    private void onFailure(HttpServletRequest request, String presentedToken, String reason) {
        String ip = RequestMetadata.clientIp(request, clientIp);
        try {
            failureLimiter.recordFailure(ip, presentedToken);
        } catch (ApiException rateLimited) {
            audit(request, "rate_limited");
            throw rateLimited;
        }
        audit(request, reason);
    }

    private void audit(HttpServletRequest request, String reason) {
        events.failure(AuthEventType.INTERNAL_ACCESS_DENIED, null, null,
                details(
                        "route", request.getRequestURI(),
                        "method", request.getMethod(),
                        "reason", reason));
    }
}
