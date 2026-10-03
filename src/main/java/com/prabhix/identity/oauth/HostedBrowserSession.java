package com.prabhix.identity.oauth;

import com.prabhix.identity.common.Secrets;
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

    public UUID establish(UUID userId,
                          HttpServletRequest request,
                          HttpServletResponse response) {
        DeviceSession session = currentSession(request);
        if (session != null && !session.getUserId().equals(userId)) {
            // A shared browser changing accounts must not leave the previous account's durable
            // credential usable by somebody who copied it before the new login overwrote it.
            sessions.revoke(session.getId(), "account_switched");
            session = null;
        }
        if (session != null) {
            // Reauthentication rotates the opaque cookie on the existing device row. A stolen copy
            // stops working immediately without filling the device list with duplicate browsers.
            session = sessions.touch(session.getId());
        } else {
            session = sessions.openOrReuse(userId, DeviceContext.of(
                    null,
                    "Web browser",
                    "WEB",
                    RequestMetadata.userAgent(request),
                    RequestMetadata.clientIp(request, clientIp)));
        }
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
