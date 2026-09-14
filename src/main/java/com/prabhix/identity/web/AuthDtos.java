package com.prabhix.identity.web;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public final class AuthDtos {

    private AuthDtos() {
    }

    /**
     * @param organizationName the workspace to create alongside the account, in the platform. Optional,
     *     and blank means an account on its own — correct for someone accepting an invitation to a
     *     workspace that already exists, and not for anybody else. Same field name and limit as the
     *     platform's register request, because a client should not be able to tell which service
     *     answered.
     */
    public record RegisterRequest(
            @NotBlank @Email String email,
            @NotBlank @Size(min = 10, max = 128) String password,
            @NotBlank @Size(max = 160) String fullName,
            @Size(max = 200) String organizationName,
            String deviceId,
            String deviceName,
            String deviceType) {
    }

    public record LoginRequest(
            @NotBlank @Email String email,
            @NotBlank String password,
            String deviceId,
            String deviceName,
            String deviceType) {
    }

    public record RefreshRequest(@NotBlank String refreshToken) {
    }

    public record LogoutRequest(String refreshToken) {
    }

    /**
     * What every sign-in flow returns.
     *
     * <p><b>No {@code organizationId} and no {@code permissions}.</b> The platform's response carried
     * both, frozen into the JWT at sign-in, which meant a revoked role kept working for up to fifteen
     * minutes. Those are product facts and each product now answers them per request from its own
     * database — see {@code IdentityClaims} for why the token deliberately cannot carry them.
     *
     * @param refreshToken absent when the caller authenticated with the browser session cookie.
     *     Native clients have no cookie jar and keep using this field; browsers no longer store it
     *     anywhere, which is the point — a token in localStorage is readable by any script that gets
     *     injected onto the page.
     * @param sessionId which device session was just established. Not a credential: it is already
     *     returned by {@code /auth/me} and listed in Settings.
     */
    public record TokenResponse(
            String accessToken,
            String refreshToken,
            long expiresInSeconds,
            UUID sessionId) {
    }

    /**
     * Who the caller is, and nothing about what they may do.
     *
     * <p>A product's own {@code /me} is what tells a client its organization, roles and permissions.
     */
    public record AuthMeResponse(
            UUID userId,
            String email,
            boolean emailVerified,
            String displayName,
            String fullName,
            String avatarUrl,
            String timezone,
            String locale,
            boolean platformAdmin,
            UUID sessionId) {
    }

    public record EmailRequest(@NotBlank @Email String email) {
    }

    public record MagicLinkVerifyRequest(
            @NotBlank String token,
            String deviceId,
            String deviceName,
            String deviceType) {
    }

    public record OtpVerifyRequest(
            @NotBlank @Email String email,
            @NotBlank String code,
            String deviceId,
            String deviceName,
            String deviceType) {
    }

    /**
     * A phone number in international form.
     *
     * <p>Not validated by pattern here. {@code PhoneAuthService} strips separators and then checks
     * E.164, and a bean-validation regex would reject {@code +91 98765 43210} before the stripping
     * that would have made it acceptable.
     */
    public record PhoneRequest(@NotBlank String phone) {
    }

    public record PhoneOtpVerifyRequest(
            @NotBlank String phone,
            @NotBlank String code,
            String deviceId,
            String deviceName,
            String deviceType) {
    }

    public record PhoneVerifyConfirmRequest(
            @NotBlank String phone,
            @NotBlank String code) {
    }

    public record PasswordResetRequest(
            @NotBlank String token,
            @NotBlank @Size(min = 10, max = 128) String newPassword) {
    }

    public record EmailVerifyConfirmRequest(@NotBlank String token) {
    }

    public record PasswordChangeRequest(
            @NotBlank String currentPassword,
            @NotBlank @Size(min = 10, max = 128) String newPassword) {
    }

    /**
     * Partial. Null leaves the field alone; a blank {@code displayName} or {@code phone} clears it.
     * {@code name} is {@code fullName} on the wire the console already uses.
     */
    public record ProfileUpdateRequest(
            @Size(max = 160) String name,
            @Size(max = 80) String displayName,
            @Size(max = 32) String phone,
            @Size(max = 64) String timezone,
            @Size(max = 16) String locale) {
    }

    public record EmailChangeRequest(@NotBlank @Email String email) {
    }

    public record EmailChangeConfirmRequest(@NotBlank String token) {
    }

    public record PasskeyView(
            UUID id,
            String label,
            Instant createdAt,
            Instant lastUsedAt,
            Boolean backedUp) {
    }

    public record GoogleSsoRequest(
            @NotBlank String idToken,
            String deviceId,
            String deviceName,
            String deviceType) {
    }

    public record AckResponse(String message) {
    }

    public record SessionView(
            UUID id,
            String deviceName,
            String deviceType,
            String ipAddress,
            Instant lastSeenAt,
            Instant createdAt,
            boolean current) {
    }

    public record SessionListResponse(List<SessionView> sessions) {
    }

    /**
     * A user record as a product mirrors it.
     *
     * <p>Only what a product needs to render a name next to a row and satisfy its own foreign keys.
     */
    public record MirroredUser(
            UUID id,
            String email,
            boolean emailVerified,
            String fullName,
            String displayName,
            String avatarUrl,
            String jobTitle,
            String timezone,
            String locale,
            String status,
            boolean platformAdmin,
            Instant updatedAt) {
    }

    public record UserLookupRequest(List<UUID> ids, List<String> emails) {
    }

    public record UserLookupResponse(List<MirroredUser> users) {
    }
}
