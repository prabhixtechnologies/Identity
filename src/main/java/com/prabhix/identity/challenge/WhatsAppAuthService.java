package com.prabhix.identity.challenge;

import com.prabhix.identity.challenge.AuthChallenge.ChallengePurpose;
import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.session.SessionService.DeviceContext;
import com.prabhix.identity.session.SignInService;
import com.prabhix.identity.user.CredentialService;
import com.prabhix.identity.user.IdentityUser;
import com.prabhix.identity.user.IdentityUserRepository;
import com.prabhix.identity.web.AuthDtos.AckResponse;
import com.prabhix.identity.web.AuthDtos.TokenResponse;
import com.prabhix.identity.whatsapp.WhatsAppSender;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Sign-in by WhatsApp code.
 *
 * <p>Same rules as {@link PhoneAuthService}: a verified number on an existing account only, never
 * account creation. The channel differs ({@link ChallengePurpose#WHATSAPP_OTP}), the trust model
 * does not — numbers are still recycled and SIM-swappable.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class WhatsAppAuthService {

    private static final Pattern E164 = Pattern.compile("^\\+[1-9]\\d{7,14}$");

    private final IdentityUserRepository users;
    private final CredentialService credentials;
    private final ChallengeService challenges;
    private final SignInService signIn;
    private final WhatsAppSender whatsApp;

    @Transactional
    public AckResponse requestOtp(String phone, String ipAddress) {
        if (!whatsApp.enabled()) {
            throw ApiException.of(ErrorCode.FEATURE_DISABLED,
                    "WhatsApp sign-in is not available on this deployment");
        }

        String normalized = normalize(phone);
        Optional<IdentityUser> user = users.findByPhoneAndPhoneVerifiedAtIsNotNullAndDeletedAtIsNull(
                normalized);

        // Same acknowledgement whether or not the number is known. Unknown numbers send nothing —
        // every WhatsApp message still costs, and the endpoint must not be a membership oracle.
        if (user.isPresent()) {
            ChallengeService.Raised raised = challenges.raise(
                    ChallengePurpose.WHATSAPP_OTP, user.get().getId(), normalized, ipAddress);
            whatsApp.send(normalized, "Your Prabhix code is " + raised.rawSecret()
                    + ". It expires in " + challenges.expiryMinutes()
                    + " minutes. Do not share it with anyone.");
        }
        return new AckResponse("If that number has an account, a code is on its way.");
    }

    @Transactional
    public IdentityUser authenticateByOtp(String phone, String code) {
        String normalized = normalize(phone);
        AuthChallenge challenge = challenges.consumeByCode(
                normalized, code, ChallengePurpose.WHATSAPP_OTP);
        IdentityUser user = credentials.requireActive(challenge.getUserId());
        credentials.resetLoginFailures(user);
        return user;
    }

    @Transactional
    public TokenResponse verifyOtp(String phone, String code, DeviceContext device) {
        return signIn.complete(authenticateByOtp(phone, code), device, List.of("whatsapp"));
    }

    public boolean enabled() {
        return whatsApp.enabled();
    }

    @Transactional
    public AckResponse requestVerification(java.util.UUID userId, String phone, String ipAddress) {
        if (!whatsApp.enabled()) {
            throw ApiException.of(ErrorCode.FEATURE_DISABLED,
                    "WhatsApp verification is not available on this deployment");
        }

        String normalized = normalize(phone);
        users.findByPhoneAndPhoneVerifiedAtIsNotNullAndDeletedAtIsNull(normalized)
                .filter(existing -> !existing.getId().equals(userId))
                .ifPresent(existing -> {
                    throw ApiException.of(ErrorCode.CONFLICT,
                            "That number is already verified on another account");
                });

        IdentityUser user = credentials.requireActive(userId);
        ChallengeService.Raised raised = challenges.raise(
                ChallengePurpose.WHATSAPP_OTP, user.getId(), normalized, ipAddress);
        whatsApp.send(normalized, "Your Prabhix verification code is " + raised.rawSecret()
                + ". It expires in " + challenges.expiryMinutes() + " minutes.");
        return new AckResponse("Code sent.");
    }

    @Transactional
    public AckResponse confirmVerification(java.util.UUID userId, String phone, String code) {
        String normalized = normalize(phone);
        AuthChallenge challenge = challenges.consumeByCode(
                normalized, code, ChallengePurpose.WHATSAPP_OTP);

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
        String stripped = phone.replaceAll("[\\s()\\-.]", "");
        if (!E164.matcher(stripped).matches()) {
            throw ApiException.of(ErrorCode.MALFORMED_REQUEST,
                    "Enter the number in international form, starting with +");
        }
        return stripped;
    }
}
