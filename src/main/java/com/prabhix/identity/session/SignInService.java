package com.prabhix.identity.session;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.common.Secrets;
import com.prabhix.identity.event.AuthEventRecorder;
import com.prabhix.identity.event.AuthEventType;
import com.prabhix.identity.session.SessionService.DeviceContext;
import com.prabhix.identity.session.SessionService.RotatedToken;
import com.prabhix.identity.token.IdentityClaims;
import com.prabhix.identity.token.TokenService;
import com.prabhix.identity.user.CredentialService;
import com.prabhix.identity.user.IdentityUser;
import com.prabhix.identity.web.AuthDtos.TokenResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static com.prabhix.identity.event.AuthEventRecorder.details;

/**
 * Turns "this person proved who they are" into tokens.
 *
 * <p>Every flow — password, magic link, OTP, SSO, cookie exchange — funnels through here so that
 * exactly one place decides what a session looks like and what a token says. The platform had this
 * logic spread across {@code AuthService}, {@code PasswordlessAuthService} and
 * {@code GoogleSsoService}, each assembling its own principal.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SignInService {

    private final SessionService sessions;
    private final CredentialService credentials;
    private final TokenService tokens;
    private final AuthEventRecorder events;

    /**
     * Completes a sign-in for a user who has already been authenticated by some means.
     *
     * @param authenticationMethods what they proved, in {@code amr} terms: {@code pwd}, {@code otp},
     *     {@code link} or a provider name. Products cannot re-derive this from anything else, and it
     *     is the only way a product can insist on, say, a password rather than a magic link before
     *     showing something sensitive.
     */
    @Transactional
    public TokenResponse complete(IdentityUser user,
                                  DeviceContext device,
                                  List<String> authenticationMethods) {
        credentials.ensureSignInAllowed(user);
        DeviceSession session = sessions.openOrReuse(user.getId(), device);
        String refreshToken = sessions.issueRefreshToken(user.getId(), session.getId());
        // The one success event for every API sign-in, whichever proof got the caller here. The
        // hosted page records its own in HostedSignIn, because it never comes through this method.
        events.success(AuthEventType.LOGIN_SUCCEEDED, user.getId(), user.getEmail(),
                details("methods", authenticationMethods,
                        "sessionId", session.getId().toString(),
                        "surface", "api",
                        "deviceType", session.getDeviceType().name()));
        return respond(user, session, refreshToken, authenticationMethods);
    }

    /** Signs in with an email and password. */
    @Transactional
    public TokenResponse withPassword(String email, String password, DeviceContext device) {
        IdentityUser user = credentials.authenticate(email, password);
        return complete(user, device, List.of("pwd"));
    }

    /** Exchanges a rotating refresh token for a new access token and its successor. */
    @Transactional
    public TokenResponse refresh(String rawRefreshToken) {
        RotatedToken rotated = sessions.rotate(rawRefreshToken);
        // A disabled account's refresh tokens stop working at the next refresh, which is the longest
        // a disable can take to bite on a native client: one access-token TTL.
        IdentityUser user = credentials.requireSignInAllowed(rotated.userId());
        // amr describes how the session was originally established, and a refresh proves nothing new
        // about the person, so it is not re-asserted here. A product that needs to know should ask
        // for a fresh sign-in rather than read a claim a refresh could have invented.
        return respond(user, rotated.session(), rotated.refreshToken(), List.of());
    }

    /**
     * Mints an access token from the shared browser session cookie.
     *
     * <p>Deliberately unlike {@link #refresh}: nothing is consumed, nothing is rotated, and no new
     * refresh token is handed out. That is what makes it safe for two console hostnames to call it at
     * the same instant — the failure this replaces was two apps racing on one rotating refresh token
     * and having the session revoked as a replay.
     *
     * <p>The response carries no refresh token. A browser has no need of one now that the cookie can
     * be exchanged again, and not returning one keeps it out of {@code localStorage}, where any
     * injected script could have read it.
     */
    @Transactional
    public TokenResponse exchangeCookie(String rawCookieToken) {
        DeviceSession session = sessions.findByCookie(Secrets.sha256(rawCookieToken))
                .orElseThrow(SignInService::noSessionCookie);

        // Distinguishing these two is not worth doing for the caller — both mean "sign in again" —
        // but the distinction matters in the log, where a revoked session is the expected
        // consequence of somebody signing out and an expired cookie is just the passage of time.
        if (!session.isActive()) {
            log.debug("Cookie exchange refused: session {} was revoked", session.getId());
            throw ApiException.of(ErrorCode.TOKEN_REVOKED, "This session was signed out");
        }
        if (!session.hasUsableCookie(Instant.now())) {
            throw noSessionCookie();
        }

        IdentityUser user = credentials.requireSignInAllowed(session.getUserId());
        DeviceSession touched = sessions.touch(session.getId());
        return respond(user, touched, null, List.of());
    }

    public static ApiException noSessionCookie() {
        return ApiException.of(ErrorCode.UNAUTHENTICATED, "No active session for this browser");
    }

    private TokenResponse respond(IdentityUser user,
                                  DeviceSession session,
                                  String refreshToken,
                                  List<String> authenticationMethods) {
        TokenService.IssuedToken access = tokens.issue(new IdentityClaims(
                user.getId(),
                user.getEmail(),
                user.isEmailVerified(),
                user.effectiveDisplayName(),
                session.getId(),
                authenticationMethods));

        return new TokenResponse(
                access.token(),
                refreshToken,
                Duration.between(Instant.now(), access.expiresAt()).toSeconds(),
                session.getId());
    }
}
