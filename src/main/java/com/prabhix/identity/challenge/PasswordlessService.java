package com.prabhix.identity.challenge;

import com.prabhix.identity.challenge.AuthChallenge.ChallengePurpose;
import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.config.IdentityProperties;
import com.prabhix.identity.mail.AuthMailer;
import com.prabhix.identity.session.SessionService.DeviceContext;
import com.prabhix.identity.session.SignInService;
import com.prabhix.identity.user.CredentialService;
import com.prabhix.identity.user.IdentityUser;
import com.prabhix.identity.web.AuthDtos.AckResponse;
import com.prabhix.identity.web.AuthDtos.TokenResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

/** Signing in without a password: magic link and emailed OTP, plus password reset. */
@Service
@RequiredArgsConstructor
public class PasswordlessService {

    /**
     * The same answer whether or not the address has an account.
     *
     * <p>Anything else turns this endpoint into a membership oracle: ask it about an address and
     * learn whether that person is a customer.
     */
    private static final AckResponse GENERIC_ACK =
            new AckResponse("If that address is registered, you will receive an email shortly.");

    private final ChallengeService challenges;
    private final CredentialService credentials;
    private final SignInService signIn;
    private final AuthMailer mailer;
    private final IdentityProperties properties;

    @Transactional
    public AckResponse requestMagicLink(String email, String ipAddress) {
        Optional<IdentityUser> user = credentials.findByEmail(email);
        if (user.isPresent()) {
            ChallengeService.Raised raised = challenges.raise(
                    ChallengePurpose.MAGIC_LINK, user.get().getId(), user.get().getEmail(), ipAddress);
            mailer.sendMagicLink(
                    user.get().getEmail(),
                    user.get().effectiveDisplayName(),
                    consoleLink("/magic-link", raised.rawSecret()),
                    challenges.expiryMinutes());
        }
        return GENERIC_ACK;
    }

    @Transactional
    public TokenResponse verifyMagicLink(String rawToken, DeviceContext device) {
        AuthChallenge challenge = challenges.consumeBySecret(rawToken, ChallengePurpose.MAGIC_LINK);
        IdentityUser user = credentials.requireActive(challenge.getUserId());
        credentials.resetLoginFailures(user);
        // A magic link proves control of the mailbox, which is exactly what email verification
        // proves, so a first sign-in by link should not then ask the user to confirm the address.
        credentials.markEmailVerified(user.getId());
        return signIn.complete(user, device, List.of("link"));
    }

    @Transactional
    public AckResponse requestOtp(String email, String ipAddress) {
        Optional<IdentityUser> user = credentials.findByEmail(email);
        if (user.isPresent()) {
            ChallengeService.Raised raised = challenges.raise(
                    ChallengePurpose.EMAIL_OTP, user.get().getId(), user.get().getEmail(), ipAddress);
            mailer.sendOtp(user.get().getEmail(), raised.rawSecret(), challenges.expiryMinutes());
        }
        return GENERIC_ACK;
    }

    @Transactional
    public TokenResponse verifyOtp(String email, String code, DeviceContext device) {
        AuthChallenge challenge = challenges.consumeByCode(email, code, ChallengePurpose.EMAIL_OTP);
        IdentityUser user = credentials.requireActive(challenge.getUserId());
        credentials.resetLoginFailures(user);
        credentials.markEmailVerified(user.getId());
        return signIn.complete(user, device, List.of("otp"));
    }

    @Transactional
    public AckResponse requestPasswordReset(String email, String ipAddress) {
        Optional<IdentityUser> user = credentials.findByEmail(email);
        if (user.isPresent()) {
            ChallengeService.Raised raised = challenges.raise(
                    ChallengePurpose.PASSWORD_RESET, user.get().getId(), user.get().getEmail(), ipAddress);
            mailer.sendPasswordReset(
                    user.get().getEmail(),
                    user.get().effectiveDisplayName(),
                    consoleLink("/reset-password", raised.rawSecret()),
                    challenges.expiryMinutes());
        }
        return GENERIC_ACK;
    }

    @Transactional
    public AckResponse resetPassword(String rawToken, String newPassword) {
        AuthChallenge challenge = challenges.consumeBySecret(rawToken, ChallengePurpose.PASSWORD_RESET);
        if (challenge.getUserId() == null) {
            throw ApiException.of(ErrorCode.TOKEN_INVALID, "That link is not valid");
        }
        credentials.setPassword(challenge.getUserId(), newPassword);
        return new AckResponse("Your password has been updated.");
    }

    /**
     * Builds a link into the console's router, not the API.
     *
     * <p>These are console paths on purpose. The two drifted apart once before and every emailed
     * magic link 404'd, so the path is spelled the way {@code web/src/routes.tsx} spells it.
     */
    private String consoleLink(String path, String rawToken) {
        return properties.urls().console() + path + "?token="
                + URLEncoder.encode(rawToken, StandardCharsets.UTF_8);
    }
}
