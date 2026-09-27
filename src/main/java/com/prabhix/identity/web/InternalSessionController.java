package com.prabhix.identity.web;

import com.prabhix.identity.event.AuthEventRecorder;
import com.prabhix.identity.event.AuthEventType;
import com.prabhix.identity.event.AuthEventType.Outcome;
import com.prabhix.identity.security.ServiceTokenAuthenticator;
import com.prabhix.identity.session.SessionService;
import com.prabhix.identity.session.SessionService.GlobalRevocationResult;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import static com.prabhix.identity.event.AuthEventRecorder.details;

/**
 * Service-authenticated session operations that apply fleet-wide, for cutover and break-glass.
 *
 * <p>Per-user revocation remains on {@link InternalUserController#revokeTokens}.
 */
@RestController
@RequestMapping("/internal/identity/sessions")
@RequiredArgsConstructor
public class InternalSessionController {

    private static final int DEFAULT_BATCH = 200;
    private static final int MAX_BATCH = 500;

    private final SessionService sessions;
    private final ServiceTokenAuthenticator serviceTokens;
    private final AuthEventRecorder events;

    @PostMapping("/revoke-all")
    public GlobalRevocationResponse revokeAll(HttpServletRequest request,
                                              @RequestParam(defaultValue = "cutover") String reason,
                                              @RequestParam(required = false) Integer batchSize) {
        serviceTokens.requireServiceToken(request);
        int batch = batchSize == null ? DEFAULT_BATCH : Math.min(Math.max(batchSize, 1), MAX_BATCH);
        GlobalRevocationResult result = sessions.revokeAllActiveGlobally(reason, batch);
        events.record(AuthEventType.ALL_SESSIONS_REVOKED, Outcome.SUCCESS, null, null,
                serviceTokens.actingUser(request).orElse(null),
                details(
                        "route", "internal/sessions/revoke-all",
                        "reason", reason,
                        "batchSize", batch,
                        "sessionsRevoked", result.sessionsRevoked(),
                        "refreshTokensRevoked", result.refreshTokensRevoked(),
                        "usersMarked", result.usersMarked()));
        return new GlobalRevocationResponse(
                result.sessionsRevoked(),
                result.refreshTokensRevoked(),
                result.usersMarked());
    }

    public record GlobalRevocationResponse(
            int sessionsRevoked,
            int refreshTokensRevoked,
            int usersMarked) {
    }
}
