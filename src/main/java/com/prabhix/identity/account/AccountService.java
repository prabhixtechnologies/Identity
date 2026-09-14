package com.prabhix.identity.account;

import com.prabhix.identity.challenge.AuthChallenge;
import com.prabhix.identity.challenge.AuthChallenge.ChallengePurpose;
import com.prabhix.identity.challenge.ChallengeService;
import com.prabhix.identity.challenge.PhoneAuthService;
import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.Emails;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.config.IdentityProperties;
import com.prabhix.identity.event.AuthEventRecorder;
import com.prabhix.identity.event.AuthEventType;
import com.prabhix.identity.mail.AuthMailer;
import com.prabhix.identity.user.AuthIdentity;
import com.prabhix.identity.user.AuthIdentity.AuthProvider;
import com.prabhix.identity.user.AuthIdentityRepository;
import com.prabhix.identity.user.CredentialService;
import com.prabhix.identity.user.IdentityUser;
import com.prabhix.identity.user.IdentityUserRepository;
import com.prabhix.identity.web.AuthDtos.AckResponse;
import com.prabhix.identity.web.AuthDtos.PasskeyView;
import com.prabhix.identity.web.AuthDtos.ProfileUpdateRequest;
import com.prabhix.identity.webauthn.WebAuthnCredential;
import com.prabhix.identity.webauthn.WebAuthnCredentialRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.UUID;

import static com.prabhix.identity.event.AuthEventRecorder.details;

/**
 * Self-service changes to an account the caller already holds.
 *
 * <p>Kept off {@code CredentialService} on purpose. That class decides whether someone may sign in;
 * this one is what they do once they have. Mixing the two is how a password change started revoking
 * the session it was made from, and how removing a passkey skipped the check that it was not the
 * last way in.
 */
@Service
@RequiredArgsConstructor
public class AccountService {

    /** How long {@code deletion_requested_at} is advisory. Nothing here acts on the timestamp. */
    public static final Duration DELETION_GRACE = Duration.ofDays(30);

    private final CredentialService credentials;
    private final IdentityUserRepository users;
    private final AuthIdentityRepository identities;
    private final WebAuthnCredentialRepository passkeys;
    private final ChallengeService challenges;
    private final AuthMailer mailer;
    private final IdentityProperties properties;
    private final AuthEventRecorder events;

    @Transactional
    public AckResponse changePassword(UUID userId, String currentPassword, String newPassword) {
        IdentityUser user = credentials.requireSignInAllowed(userId);
        if (!user.hasPassword() || !credentials.matchesPassword(user, currentPassword)) {
            // Not INVALID_CREDENTIALS and not a failed-login increment: this is not a sign-in, and
            // treating it as one would lock the person out of the page they are using to recover.
            events.failure(AuthEventType.PASSWORD_CHANGED, user.getId(), user.getEmail(),
                    details("reason", "incorrect_current"));
            throw ApiException.of(ErrorCode.PASSWORD_INCORRECT, "The current password is not correct");
        }
        credentials.replacePassword(user, newPassword);
        events.success(AuthEventType.PASSWORD_CHANGED, user.getId(), user.getEmail(), details());
        return new AckResponse("Your password has been updated.");
    }

    /**
     * Sets a password from the hosted account page when the account has never had one.
     *
     * <p>The API change endpoint always asks for the current password, because a bearer client can
     * be a stolen token. The hosted page has a fresh login session, so an account that only ever
     * used Google or a passkey can add a password without inventing a current one.
     */
    @Transactional
    public AckResponse setPasswordFromHosted(UUID userId, String newPassword) {
        IdentityUser user = credentials.requireSignInAllowed(userId);
        if (user.hasPassword()) {
            throw ApiException.of(ErrorCode.VALIDATION_FAILED,
                    "Enter your current password to choose a new one");
        }
        credentials.replacePassword(user, newPassword);
        events.success(AuthEventType.PASSWORD_SET, user.getId(), user.getEmail(),
                details("surface", "hosted"));
        return new AckResponse("Your password has been set.");
    }

    @Transactional
    public AckResponse updateProfile(UUID userId, ProfileUpdateRequest request) {
        IdentityUser user = credentials.requireSignInAllowed(userId);
        if (request.name() != null) {
            if (request.name().isBlank()) {
                throw ApiException.of(ErrorCode.VALIDATION_FAILED, "Enter a name");
            }
            user.setFullName(request.name().trim());
        }
        if (request.displayName() != null) {
            String display = request.displayName().trim();
            user.setDisplayName(display.isEmpty() ? null : display);
        }
        if (request.phone() != null) {
            applyPhone(user, request.phone());
        }
        if (request.timezone() != null) {
            user.setTimezone(requireZone(request.timezone()));
        }
        if (request.locale() != null) {
            String locale = request.locale().trim();
            if (locale.isEmpty() || locale.length() > 16) {
                throw ApiException.of(ErrorCode.VALIDATION_FAILED, "That locale is not valid");
            }
            user.setLocale(locale);
        }
        users.save(user);
        events.success(AuthEventType.PROFILE_UPDATED, user.getId(), user.getEmail(), details());
        return new AckResponse("Your profile has been updated.");
    }

    @Transactional
    public AckResponse requestEmailChange(UUID userId, String newEmail, String ipAddress) {
        IdentityUser user = credentials.requireSignInAllowed(userId);
        String destination = Emails.normalize(newEmail);
        if (destination.equals(user.getEmail())) {
            throw ApiException.of(ErrorCode.VALIDATION_FAILED, "That is already your address");
        }
        if (users.activeEmailExists(destination)) {
            throw ApiException.of(ErrorCode.ALREADY_EXISTS, "An account already uses that email");
        }

        ChallengeService.Raised raised = challenges.raise(
                ChallengePurpose.EMAIL_CHANGE, user.getId(), destination, ipAddress);
        mailer.sendEmailChange(
                destination,
                user.effectiveDisplayName(),
                properties.issuer() + "/account/email/confirm?token="
                        + URLEncoder.encode(raised.rawSecret(), StandardCharsets.UTF_8),
                challenges.expiryMinutes());
        events.success(AuthEventType.EMAIL_CHANGE_REQUESTED, user.getId(), user.getEmail(),
                details("newEmail", destination));
        return new AckResponse("Check the new address for a confirmation link.");
    }

    /**
     * Public: the secret in the link is the authentication, the way a magic link is.
     *
     * <p>The address is taken from the challenge's destination, not from the caller, so a stolen
     * session cannot point a legitimate token at a different mailbox.
     */
    @Transactional
    public AckResponse confirmEmailChange(String rawToken) {
        AuthChallenge challenge = challenges.consumeBySecret(rawToken, ChallengePurpose.EMAIL_CHANGE);
        if (challenge.getUserId() == null || challenge.getDestination() == null) {
            throw ApiException.of(ErrorCode.TOKEN_INVALID, "That link is not valid");
        }
        IdentityUser user = credentials.requireActive(challenge.getUserId());
        String destination = challenge.getDestination();
        if (users.activeEmailExists(destination)
                && !destination.equals(user.getEmail())) {
            throw ApiException.of(ErrorCode.ALREADY_EXISTS, "An account already uses that email");
        }
        String previous = user.getEmail();
        user.setEmail(destination);
        user.setEmailVerifiedAt(Instant.now());
        users.save(user);
        events.success(AuthEventType.EMAIL_CHANGED, user.getId(), destination,
                details("previousEmail", previous));
        return new AckResponse("Your email has been updated.");
    }

    @Transactional(readOnly = true)
    public List<PasskeyView> listPasskeys(UUID userId) {
        credentials.requireSignInAllowed(userId);
        return passkeys.findByUserId(userId).stream()
                .map(row -> new PasskeyView(
                        row.getId(),
                        row.getLabel(),
                        row.getCreatedAt(),
                        row.getLastUsedAt(),
                        row.getBackedUp()))
                .toList();
    }

    @Transactional
    public void removePasskey(UUID userId, UUID passkeyId) {
        IdentityUser user = credentials.requireSignInAllowed(userId);
        WebAuthnCredential row = passkeys.findByIdAndUserId(passkeyId, userId)
                .orElseThrow(() -> ApiException.notFound("That passkey"));
        refuseIfLastFactor(user, Factor.PASSKEY);
        passkeys.delete(row);
        events.success(AuthEventType.PASSKEY_REMOVED, user.getId(), user.getEmail(),
                details("passkeyId", passkeyId.toString(),
                        "label", row.getLabel()));
    }

    @Transactional
    public void unlinkGoogle(UUID userId) {
        IdentityUser user = credentials.requireSignInAllowed(userId);
        AuthIdentity identity = identities.findByUserIdAndProvider(userId, AuthProvider.GOOGLE)
                .orElseThrow(() -> ApiException.notFound("That Google account"));
        refuseIfLastFactor(user, Factor.GOOGLE);
        identities.delete(identity);
        events.success(AuthEventType.GOOGLE_UNLINKED, user.getId(), user.getEmail(),
                details("providerEmail", identity.getProviderEmail()));
    }

    @Transactional
    public AckResponse requestDeletion(UUID userId) {
        IdentityUser user = credentials.requireSignInAllowed(userId);
        if (user.getDeletionRequestedAt() == null) {
            user.setDeletionRequestedAt(Instant.now());
            users.save(user);
        }
        events.success(AuthEventType.DELETION_REQUESTED, user.getId(), user.getEmail(),
                details("graceDays", DELETION_GRACE.toDays()));
        return new AckResponse("Your account is scheduled for deletion.");
    }

    @Transactional
    public AckResponse cancelDeletion(UUID userId) {
        IdentityUser user = credentials.requireSignInAllowed(userId);
        user.setDeletionRequestedAt(null);
        users.save(user);
        events.success(AuthEventType.DELETION_CANCELLED, user.getId(), user.getEmail(), details());
        return new AckResponse("Account deletion has been cancelled.");
    }

    @Transactional(readOnly = true)
    public AccountSnapshot snapshot(UUID userId) {
        IdentityUser user = credentials.requireSignInAllowed(userId);
        return new AccountSnapshot(
                user,
                passkeys.findByUserId(userId),
                identities.findByUserIdAndProvider(userId, AuthProvider.GOOGLE).orElse(null),
                user.getDeletionRequestedAt() == null
                        ? null
                        : user.getDeletionRequestedAt().plus(DELETION_GRACE));
    }

    public boolean googleLinked(UUID userId) {
        return identities.existsByUserIdAndProvider(userId, AuthProvider.GOOGLE);
    }

    /**
     * Password, Google, passkeys. Magic-link and OTP are not counted: they are always available for
     * an address, so treating them as a remaining factor would let somebody delete the last thing
     * they actually registered and then find they can only get in through email they may no longer
     * control in a year.
     */
    private void refuseIfLastFactor(IdentityUser user, Factor removing) {
        boolean password = user.hasPassword();
        boolean google = googleLinked(user.getId());
        long passkeyCount = passkeys.countByUserId(user.getId());
        boolean remainingPassword = password;
        boolean remainingGoogle = google && removing != Factor.GOOGLE;
        boolean remainingPasskey = (passkeyCount - (removing == Factor.PASSKEY ? 1 : 0)) > 0;
        if (remainingPassword || remainingGoogle || remainingPasskey) {
            return;
        }
        events.denied(removing == Factor.GOOGLE ? AuthEventType.GOOGLE_UNLINKED : AuthEventType.PASSKEY_REMOVED,
                user.getId(), user.getEmail(),
                details("reason", "last_factor"));
        throw ApiException.of(ErrorCode.LAST_CREDENTIAL,
                "That is the only way to sign in to this account. Add another before removing it.");
    }

    private void applyPhone(IdentityUser user, String phone) {
        if (phone.isBlank()) {
            user.setPhone(null);
            user.setPhoneVerifiedAt(null);
            return;
        }
        String normalized = PhoneAuthService.normalize(phone);
        if (!normalized.equals(user.getPhone())) {
            user.setPhone(normalized);
            user.setPhoneVerifiedAt(null);
        }
    }

    private static String requireZone(String timezone) {
        String trimmed = timezone.trim();
        if (trimmed.isEmpty()) {
            throw ApiException.of(ErrorCode.VALIDATION_FAILED, "Enter a timezone");
        }
        try {
            ZoneId.of(trimmed);
        } catch (RuntimeException ex) {
            throw ApiException.of(ErrorCode.VALIDATION_FAILED, "That timezone is not valid");
        }
        return trimmed;
    }

    private enum Factor {
        PASSKEY, GOOGLE
    }

    public record AccountSnapshot(
            IdentityUser user,
            List<WebAuthnCredential> passkeys,
            AuthIdentity google,
            Instant deletionDueAt) {

        public boolean googleLinked() {
            return google != null;
        }
    }
}
