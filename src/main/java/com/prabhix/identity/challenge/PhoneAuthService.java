package com.prabhix.identity.challenge;

import com.prabhix.identity.challenge.AuthChallenge.ChallengePurpose;
import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.session.SessionService.DeviceContext;
import com.prabhix.identity.session.SignInService;
import com.prabhix.identity.sms.SmsSender;
import com.prabhix.identity.user.CredentialService;
import com.prabhix.identity.user.IdentityUser;
import com.prabhix.identity.user.IdentityUserRepository;
import com.prabhix.identity.web.AuthDtos.AckResponse;
import com.prabhix.identity.web.AuthDtos.TokenResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Sign-in by SMS code.
 *
 * <p>Deliberately not account creation. A phone number is a weaker identifier than it looks: numbers
 * are recycled by carriers, so whoever is issued a number next inherits any account bound to it, and
 * SIM swap makes it an attacker-reachable factor rather than a secret. So this signs in an existing
 * account whose number is already verified, and registering a number is a deliberate act taken from
 * inside a session — not something that can happen to you because somebody typed your number.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PhoneAuthService {

    /**
     * E.164: a plus, a non-zero country code, then up to fourteen digits.
     *
     * <p>Normalised to this one form on the way in, because the challenge is looked up by destination
     * string. {@code +91 98765 43210} and {@code +919876543210} are the same number and would be two
     * different rows, so the code sent for one would never be found when verifying the other.
     */
    private static final Pattern E164 = Pattern.compile("^\\+[1-9]\\d{7,14}$");

    private final IdentityUserRepository users;
    private final CredentialService credentials;
    private final ChallengeService challenges;
    private final SignInService signIn;
    private final SmsSender sms;

    @Transactional
    public AckResponse requestOtp(String phone, String ipAddress) {
        if (!sms.enabled()) {
            throw ApiException.of(ErrorCode.FEATURE_DISABLED,
                    "Phone sign-in is not available on this deployment");
        }

        String normalized = normalize(phone);
        Optional<IdentityUser> user = users.findByPhoneAndPhoneVerifiedAtIsNotNullAndDeletedAtIsNull(
                normalized);

        // Same acknowledgement whether or not the number is known, so this endpoint cannot be used to
        // ask "does this person have an account". Unlike email, where the cost of a wrong guess is one
        // unwanted message, here it is one paid SMS — so an unknown number sends nothing at all.
        if (user.isPresent()) {
            ChallengeService.Raised raised = challenges.raise(
                    ChallengePurpose.SMS_OTP, user.get().getId(), normalized, ipAddress);
            sms.send(normalized, "Your Prabhix code is " + raised.rawSecret()
                    + ". It expires in " + challenges.expiryMinutes()
                    + " minutes. Do not share it with anyone.");
        }
        return new AckResponse("If that number has an account, a code is on its way.");
    }

    /** Consumes an SMS code and returns whose it was, issuing nothing. */
    @Transactional
    public IdentityUser authenticateByOtp(String phone, String code) {
        String normalized = normalize(phone);
        AuthChallenge challenge = challenges.consumeByCode(
                normalized, code, ChallengePurpose.SMS_OTP);
        IdentityUser user = credentials.requireActive(challenge.getUserId());
        credentials.resetLoginFailures(user);
        return user;
    }

    @Transactional
    public TokenResponse verifyOtp(String phone, String code, DeviceContext device) {
        return signIn.complete(authenticateByOtp(phone, code), device, List.of("sms"));
    }

    /** Whether this deployment can send an SMS at all, which decides if the page offers the option. */
    public boolean enabled() {
        return sms.enabled();
    }

    /**
     * Binds a number to the signed-in account, after proving control of it.
     *
     * <p>Two steps rather than one, and started from inside a session on purpose: this is what makes
     * the number a factor the account owner chose rather than one an attacker asserted.
     */
    @Transactional
    public AckResponse requestVerification(java.util.UUID userId, String phone, String ipAddress) {
        if (!sms.enabled()) {
            throw ApiException.of(ErrorCode.FEATURE_DISABLED,
                    "Phone verification is not available on this deployment");
        }

        String normalized = normalize(phone);
        // Refused rather than moved. Silently reassigning a number would let anyone claim somebody
        // else's second factor by typing it, and the victim would find out at their next sign-in.
        users.findByPhoneAndPhoneVerifiedAtIsNotNullAndDeletedAtIsNull(normalized)
                .filter(existing -> !existing.getId().equals(userId))
                .ifPresent(existing -> {
                    throw ApiException.of(ErrorCode.CONFLICT,
                            "That number is already verified on another account");
                });

        IdentityUser user = credentials.requireActive(userId);
        ChallengeService.Raised raised = challenges.raise(
                ChallengePurpose.SMS_OTP, user.getId(), normalized, ipAddress);
        sms.send(normalized, "Your Prabhix verification code is " + raised.rawSecret()
                + ". It expires in " + challenges.expiryMinutes() + " minutes.");
        return new AckResponse("Code sent.");
    }

    @Transactional
    public AckResponse confirmVerification(java.util.UUID userId, String phone, String code) {
        String normalized = normalize(phone);
        AuthChallenge challenge = challenges.consumeByCode(
                normalized, code, ChallengePurpose.SMS_OTP);

        // The challenge names a user, and so does the session. They have to be the same person, or a
        // code sent to one account could be redeemed to bind a number to another.
        if (!userId.equals(challenge.getUserId())) {
            throw ApiException.of(ErrorCode.OTP_INVALID, "That code is not correct");
        }

        IdentityUser user = credentials.requireActive(userId);
        user.setPhone(normalized);
        user.setPhoneVerifiedAt(Instant.now());
        users.save(user);
        return new AckResponse("Number verified.");
    }

    private String normalize(String phone) {
        if (phone == null) {
            throw ApiException.of(ErrorCode.MALFORMED_REQUEST, "Enter a phone number");
        }
        // Strips the separators people type; does not guess a country code. Guessing would silently
        // send a code to a number in the wrong country and look like a delivery failure.
        String stripped = phone.replaceAll("[\\s()\\-.]", "");
        if (!E164.matcher(stripped).matches()) {
            throw ApiException.of(ErrorCode.MALFORMED_REQUEST,
                    "Enter the number in international form, starting with +");
        }
        return stripped;
    }
}
