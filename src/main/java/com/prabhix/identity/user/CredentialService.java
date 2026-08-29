package com.prabhix.identity.user;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.config.IdentityProperties;
import com.prabhix.identity.token.TokenDenyList;
import com.prabhix.identity.user.IdentityUser.UserStatus;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Accounts and the credentials on them: creation, password verification, lockout, verification state.
 *
 * <p>This is the half of the platform's {@code UserService} that had to move. The other half —
 * profile edits, avatars, notification preferences, default organization — stayed, because none of
 * it is needed to decide whether someone may sign in.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialService {

    private final IdentityUserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final TokenDenyList denyList;
    private final IdentityProperties properties;

    @Transactional(readOnly = true)
    public Optional<IdentityUser> findByEmail(String email) {
        return users.findActiveByEmail(email);
    }

    @Transactional(readOnly = true)
    public IdentityUser requireActive(UUID userId) {
        return users.findByIdAndDeletedAtIsNull(userId)
                .orElseThrow(() -> ApiException.notFound("That account"));
    }

    @Transactional
    public IdentityUser create(String email, String rawPassword, String fullName) {
        validatePasswordStrength(rawPassword);
        IdentityUser user = newUser(email, fullName);
        user.setPasswordHash(passwordEncoder.encode(rawPassword));
        user.setPasswordChangedAt(Instant.now());
        return users.save(user);
    }

    /** For magic-link, OTP and SSO sign-ups, which never set a password. */
    @Transactional
    public IdentityUser createPasswordless(String email, String fullName) {
        return users.save(newUser(email, fullName));
    }

    private IdentityUser newUser(String email, String fullName) {
        if (users.activeEmailExists(email)) {
            throw ApiException.of(ErrorCode.ALREADY_EXISTS, "An account already uses that email");
        }
        IdentityUser user = new IdentityUser();
        user.setEmail(email);
        user.setFullName(fullName == null || fullName.isBlank() ? user.getEmail() : fullName.trim());
        user.setStatus(UserStatus.ACTIVE);
        return user;
    }

    /**
     * Verifies a password, refusing the accounts that must not sign in at all.
     *
     * <p>The order matters. Disabled and locked are checked before the password so that an operator
     * reading the log can tell "this account is locked" from "someone is guessing at it", and the
     * failure counter is only advanced for an attempt that could otherwise have succeeded.
     *
     * @throws ApiException with {@code INVALID_CREDENTIALS} for a wrong password, deliberately the
     *     same code and message the caller gets for an address with no account
     */
    @Transactional
    public IdentityUser authenticate(String email, String rawPassword) {
        Optional<IdentityUser> found = findByEmail(email);
        if (found.isEmpty()) {
            // No address in the message or the log line. An address typed at a login form is often
            // a real one belonging to somebody who is not the person typing it.
            log.debug("Sign-in attempt for an address with no account");
            throw invalidCredentials();
        }

        IdentityUser user = found.get();
        if (user.getStatus() == UserStatus.DISABLED) {
            throw ApiException.of(ErrorCode.ACCOUNT_DISABLED, "This account has been disabled");
        }
        if (user.isLockedNow()) {
            throw ApiException.of(ErrorCode.ACCOUNT_LOCKED,
                    "This account is temporarily locked. Try again later.");
        }
        if (user.getPasswordHash() == null
                || !passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
            recordLoginFailure(user);
            throw invalidCredentials();
        }

        resetLoginFailures(user);
        return user;
    }

    private ApiException invalidCredentials() {
        return ApiException.of(ErrorCode.INVALID_CREDENTIALS, "Email or password is not correct");
    }

    @Transactional
    public void recordLoginFailure(IdentityUser user) {
        user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);
        if (user.getFailedLoginAttempts() >= properties.lockout().maxFailedAttempts()) {
            user.setLockedUntil(Instant.now().plus(properties.lockout().duration()));
            user.setStatus(UserStatus.LOCKED);
        }
        users.save(user);
    }

    @Transactional
    public void resetLoginFailures(IdentityUser user) {
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        if (user.getStatus() == UserStatus.LOCKED) {
            user.setStatus(UserStatus.ACTIVE);
        }
        user.setLastLoginAt(Instant.now());
        users.save(user);
    }

    /**
     * Sets a new password and revokes everything issued before it.
     *
     * <p>The deny-list entry is user-scoped and timestamped rather than a flat marker, so signing in
     * again immediately afterwards — the expected thing to do after a reset — works instead of being
     * refused for the rest of the access-token TTL.
     */
    @Transactional
    public void setPassword(UUID userId, String rawPassword) {
        validatePasswordStrength(rawPassword);
        IdentityUser user = requireActive(userId);
        user.setPasswordHash(passwordEncoder.encode(rawPassword));
        user.setPasswordChangedAt(Instant.now());
        users.save(user);
        denyList.revokeUser(userId);
    }

    @Transactional
    public void markEmailVerified(UUID userId) {
        IdentityUser user = requireActive(userId);
        if (user.getEmailVerifiedAt() == null) {
            user.setEmailVerifiedAt(Instant.now());
            users.save(user);
        }
    }

    private void validatePasswordStrength(String rawPassword) {
        int minimum = properties.password().minLength();
        if (rawPassword == null || rawPassword.length() < minimum) {
            throw ApiException.of(ErrorCode.VALIDATION_FAILED,
                    "Password must be at least " + minimum + " characters");
        }
    }
}
