package com.prabhix.identity.oauth;

import com.prabhix.identity.common.Secrets;
import com.prabhix.identity.event.AuthEventRecorder;
import com.prabhix.identity.event.AuthEventType;
import com.prabhix.identity.observability.AuthMetrics;
import com.prabhix.identity.risk.RiskEvaluator;
import com.prabhix.identity.security.RequestMetadata;
import com.prabhix.identity.security.TrustedClientIpResolver;
import com.prabhix.identity.session.DeviceSession;
import com.prabhix.identity.session.SessionCookieService;
import com.prabhix.identity.session.SessionService;
import com.prabhix.identity.session.SessionService.DeviceContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.UUID;

import static com.prabhix.identity.event.AuthEventRecorder.details;

/**
 * Establishes the durable, revocable half of a hosted browser sign-in.
 *
 * <p>The servlet session remains deliberately short-lived: it holds an authorization request while
 * the person signs in and enables prompt-less SSO while it is active. The opaque HttpOnly cookie
 * established here is the longer-lived credential. Products exchange it for short access tokens,
 * so neither an access token nor a refresh token has to live in JavaScript storage.
 *
 * <p>Every hosted authentication method must pass through this service. Otherwise the login appears
 * successful but the first access-token expiry cannot be renewed after the servlet session idles
 * out, which turns ordinary browser inactivity into an unexpected sign-out.
 */
@Service
@RequiredArgsConstructor
public class HostedBrowserSession {

    private final SessionService sessions;
    private final SessionCookieService cookies;
    private final TrustedClientIpResolver clientIp;
    private final RiskEvaluator risk;
    private final AuthMetrics metrics;
    private final AuthEventRecorder events;

    /**
     * @param mfa {@code true} when the proof was a passkey or a one-time code. Password sign-in passes
     *     {@code false}. Staff never reach here on a password: that attempt is refused first.
     */
    public UUID establish(UUID userId,
                          HttpServletRequest request,
                          HttpServletResponse response,
                          boolean mfa) {
        String ipAddress = RequestMetadata.clientIp(request, clientIp);
        DeviceSession session = currentSession(request);
        if (session != null && !session.getUserId().equals(userId)) {
            // A shared browser changing accounts must not leave the previous account's durable
            // credential usable by somebody who copied it before the new login overwrote it.
            sessions.revoke(session.getId(), "account_switched");
            session = null;
        }
        if (session == null) {
            session = sessions.openOrReuse(userId, DeviceContext.of(
                    null,
                    "Web browser",
                    "WEB",
                    RequestMetadata.userAgent(request),
                    ipAddress));
            if (session.isNewlyOpened() && risk.newDevice() == RiskEvaluator.Decision.ALLOW) {
                metrics.newDevice();
                events.success(AuthEventType.NEW_DEVICE, userId, null,
                        details("sessionId", session.getId().toString(), "surface", "hosted"));
            }
        }
        // Always, including a reused row. touch() would leave the old network in place, and the next
        // staff cookie exchange would demand another code for a change this sign-in just confirmed.
        session = sessions.recordAuthentication(session.getId(), ipAddress, mfa);
        cookies.issueRequired(response, session.getId());
        return session.getId();
    }

    private DeviceSession currentSession(HttpServletRequest request) {
        return cookies.read(request)
                .flatMap(raw -> sessions.findByCookie(Secrets.sha256(raw)))
                .filter(DeviceSession::isActive)
                .orElse(null);
    }
}
