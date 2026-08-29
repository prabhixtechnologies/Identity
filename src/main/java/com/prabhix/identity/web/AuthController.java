package com.prabhix.identity.web;

import com.prabhix.identity.challenge.EmailVerificationService;
import com.prabhix.identity.challenge.PasswordlessService;
import com.prabhix.identity.security.AuthenticatedCaller;
import com.prabhix.identity.session.DeviceSession;
import com.prabhix.identity.session.SessionCookieService;
import com.prabhix.identity.session.SessionService;
import com.prabhix.identity.session.SessionService.DeviceContext;
import com.prabhix.identity.session.SignInService;
import com.prabhix.identity.sso.GoogleSsoService;
import com.prabhix.identity.user.CredentialService;
import com.prabhix.identity.user.IdentityUser;
import com.prabhix.identity.web.AuthDtos.AckResponse;
import com.prabhix.identity.web.AuthDtos.AuthMeResponse;
import com.prabhix.identity.web.AuthDtos.EmailRequest;
import com.prabhix.identity.web.AuthDtos.EmailVerifyConfirmRequest;
import com.prabhix.identity.web.AuthDtos.GoogleSsoRequest;
import com.prabhix.identity.web.AuthDtos.LoginRequest;
import com.prabhix.identity.web.AuthDtos.LogoutRequest;
import com.prabhix.identity.web.AuthDtos.MagicLinkVerifyRequest;
import com.prabhix.identity.web.AuthDtos.OtpVerifyRequest;
import com.prabhix.identity.web.AuthDtos.PasswordResetRequest;
import com.prabhix.identity.web.AuthDtos.RefreshRequest;
import com.prabhix.identity.web.AuthDtos.RegisterRequest;
import com.prabhix.identity.web.AuthDtos.SessionListResponse;
import com.prabhix.identity.web.AuthDtos.SessionView;
import com.prabhix.identity.web.AuthDtos.TokenResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/**
 * Every authentication flow, on the paths the platform already serves them.
 *
 * <p>The paths are unchanged from {@code com.prabhix.platform.auth.web.AuthController} on purpose:
 * Caddy routes {@code /api/v1/auth/*} here, so no client has to learn a new URL for the extraction to
 * land. Two things did change, and both are the point of the split — the response no longer carries
 * an organization or a permission set, and {@code /auth/me} answers who you are rather than what you
 * can do.
 */
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final SignInService signIn;
    private final SessionService sessions;
    private final SessionCookieService cookies;
    private final CredentialService credentials;
    private final PasswordlessService passwordless;
    private final EmailVerificationService emailVerification;
    private final GoogleSsoService googleSso;

    @PostMapping("/register")
    public TokenResponse register(@Valid @RequestBody RegisterRequest request,
                                  HttpServletRequest httpRequest,
                                  HttpServletResponse httpResponse) {
        // No organizationName, unlike the platform's register: creating an organization is a platform
        // action, and this service does not know what an organization is. The console calls
        // POST /organizations with the token it gets back.
        IdentityUser user = credentials.create(request.email(), request.password(), request.fullName());
        TokenResponse response = signIn.complete(user, device(request.deviceId(), request.deviceName(),
                request.deviceType(), httpRequest), List.of("pwd"));
        cookies.issue(httpResponse, response.sessionId());
        return response;
    }

    @PostMapping("/login")
    public TokenResponse login(@Valid @RequestBody LoginRequest request,
                               HttpServletRequest httpRequest,
                               HttpServletResponse httpResponse) {
        TokenResponse response = signIn.withPassword(request.email(), request.password(),
                device(request.deviceId(), request.deviceName(), request.deviceType(), httpRequest));
        cookies.issue(httpResponse, response.sessionId());
        return response;
    }

    @PostMapping("/refresh")
    public TokenResponse refresh(@Valid @RequestBody RefreshRequest request,
                                 HttpServletResponse httpResponse) {
        TokenResponse response = signIn.refresh(request.refreshToken());
        // Re-issued so a long-lived native session keeps the browser cookie alive too, on the same
        // device. Harmless for a client with no cookie jar, which simply ignores the header.
        cookies.issue(httpResponse, response.sessionId());
        return response;
    }

    /**
     * Exchanges the shared browser session cookie for an access token.
     *
     * <p>POST rather than GET despite reading nothing: a GET would be fetchable as a subresource from
     * any page, and the response contains a bearer token.
     */
    @PostMapping("/session/token")
    public TokenResponse sessionToken(HttpServletRequest request, HttpServletResponse response) {
        return cookies.exchange(request, response);
    }

    @PostMapping("/logout")
    public void logout(@AuthenticationPrincipal AuthenticatedCaller caller,
                       @RequestBody(required = false) LogoutRequest request,
                       HttpServletResponse response) {
        sessions.revoke(caller.sessionId(), "logout");
        if (request != null) {
            sessions.revokeRefreshToken(request.refreshToken());
        }
        cookies.clear(response);
    }

    @GetMapping("/me")
    public AuthMeResponse me(@AuthenticationPrincipal AuthenticatedCaller caller) {
        IdentityUser user = credentials.requireActive(caller.userId());
        return new AuthMeResponse(
                user.getId(),
                user.getEmail(),
                user.isEmailVerified(),
                user.effectiveDisplayName(),
                user.getFullName(),
                user.getAvatarUrl(),
                user.getTimezone(),
                user.getLocale(),
                user.isPlatformAdmin(),
                caller.sessionId());
    }

    @GetMapping("/sessions")
    public SessionListResponse sessions(@AuthenticationPrincipal AuthenticatedCaller caller) {
        List<SessionView> views = sessions.listActive(caller.userId()).stream()
                .map(session -> toView(session, caller.sessionId()))
                .toList();
        return new SessionListResponse(views);
    }

    @DeleteMapping("/sessions/{id}")
    public void revokeSession(@AuthenticationPrincipal AuthenticatedCaller caller,
                              @PathVariable UUID id) {
        sessions.revokeOwn(caller.userId(), id);
    }

    @PostMapping("/magic-link/request")
    public AckResponse requestMagicLink(@Valid @RequestBody EmailRequest request,
                                       HttpServletRequest httpRequest) {
        return passwordless.requestMagicLink(request.email(), clientIp(httpRequest));
    }

    @PostMapping("/magic-link/verify")
    public TokenResponse verifyMagicLink(@Valid @RequestBody MagicLinkVerifyRequest request,
                                        HttpServletRequest httpRequest,
                                        HttpServletResponse httpResponse) {
        TokenResponse response = passwordless.verifyMagicLink(request.token(),
                device(request.deviceId(), request.deviceName(), request.deviceType(), httpRequest));
        cookies.issue(httpResponse, response.sessionId());
        return response;
    }

    @PostMapping("/otp/request")
    public AckResponse requestOtp(@Valid @RequestBody EmailRequest request,
                                  HttpServletRequest httpRequest) {
        return passwordless.requestOtp(request.email(), clientIp(httpRequest));
    }

    @PostMapping("/otp/verify")
    public TokenResponse verifyOtp(@Valid @RequestBody OtpVerifyRequest request,
                                   HttpServletRequest httpRequest,
                                   HttpServletResponse httpResponse) {
        TokenResponse response = passwordless.verifyOtp(request.email(), request.code(),
                device(request.deviceId(), request.deviceName(), request.deviceType(), httpRequest));
        cookies.issue(httpResponse, response.sessionId());
        return response;
    }

    @PostMapping("/password/forgot")
    public AckResponse forgotPassword(@Valid @RequestBody EmailRequest request,
                                      HttpServletRequest httpRequest) {
        return passwordless.requestPasswordReset(request.email(), clientIp(httpRequest));
    }

    @PostMapping("/password/reset")
    public AckResponse resetPassword(@Valid @RequestBody PasswordResetRequest request) {
        return passwordless.resetPassword(request.token(), request.newPassword());
    }

    @PostMapping("/email/verify/request")
    public AckResponse requestEmailVerification(@AuthenticationPrincipal AuthenticatedCaller caller,
                                                HttpServletRequest httpRequest) {
        return emailVerification.request(caller.userId(), clientIp(httpRequest));
    }

    @PostMapping("/email/verify/confirm")
    public AckResponse confirmEmailVerification(@Valid @RequestBody EmailVerifyConfirmRequest request) {
        return emailVerification.confirm(request.token());
    }

    @PostMapping("/sso/google")
    public TokenResponse googleSso(@Valid @RequestBody GoogleSsoRequest request,
                                   HttpServletRequest httpRequest,
                                   HttpServletResponse httpResponse) {
        TokenResponse response = googleSso.authenticate(request.idToken(),
                device(request.deviceId(), request.deviceName(), request.deviceType(), httpRequest));
        cookies.issue(httpResponse, response.sessionId());
        return response;
    }

    private SessionView toView(DeviceSession session, UUID currentSessionId) {
        return new SessionView(
                session.getId(),
                session.getDeviceName(),
                session.getDeviceType().name(),
                session.getIpAddress(),
                session.getLastSeenAt(),
                session.getCreatedAt(),
                session.getId().equals(currentSessionId));
    }

    private DeviceContext device(String deviceId,
                                 String deviceName,
                                 String deviceType,
                                 HttpServletRequest request) {
        return DeviceContext.of(deviceId, deviceName, deviceType,
                request.getHeader("User-Agent"), clientIp(request));
    }

    /**
     * The caller's address as seen past the reverse proxy.
     *
     * <p>Only the first hop of {@code X-Forwarded-For} is taken, and only because Caddy sets it: the
     * header is client-supplied, so anything further along the chain is whatever the client wrote
     * there. It is used for rate limiting and for the audit trail on a challenge, never for access
     * decisions.
     */
    private String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
