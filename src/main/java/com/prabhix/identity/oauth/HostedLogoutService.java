package com.prabhix.identity.oauth;

import com.prabhix.identity.common.Secrets;
import com.prabhix.identity.event.AuthEventRecorder;
import com.prabhix.identity.event.AuthEventType;
import com.prabhix.identity.session.SessionCookieService;
import com.prabhix.identity.session.SessionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.UUID;

import static com.prabhix.identity.event.AuthEventRecorder.details;

/** Ends the hosted browser session without relying on Spring Security's logout filter. */
@Service
@RequiredArgsConstructor
public class HostedLogoutService {

    private final SessionCookieService sessionCookies;
    private final SessionService sessions;
    private final AuthEventRecorder events;

    public void signOut(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        sessionCookies.read(request).ifPresent(raw ->
                sessions.findByCookie(Secrets.sha256(raw)).ifPresent(session ->
                        sessions.revoke(session.getId(), "logout")));

        sessionCookies.clear(response);

        if (authentication != null) {
            hostedUserId(authentication.getName()).ifPresent(userId ->
                    events.success(AuthEventType.LOGOUT, userId, null,
                            details("surface", "hosted")));
        }

        SecurityContextHolder.clearContext();
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
    }

    private static java.util.Optional<UUID> hostedUserId(String principalName) {
        try {
            return java.util.Optional.of(UUID.fromString(principalName));
        } catch (IllegalArgumentException | NullPointerException ex) {
            return java.util.Optional.empty();
        }
    }
}
