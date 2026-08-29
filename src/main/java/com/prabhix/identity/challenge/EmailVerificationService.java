package com.prabhix.identity.challenge;

import com.prabhix.identity.challenge.AuthChallenge.ChallengePurpose;
import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.config.IdentityProperties;
import com.prabhix.identity.mail.AuthMailer;
import com.prabhix.identity.user.CredentialService;
import com.prabhix.identity.user.IdentityUser;
import com.prabhix.identity.web.AuthDtos.AckResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/** Confirming that an address belongs to the person who signed up with it. */
@Service
@RequiredArgsConstructor
public class EmailVerificationService {

    private final ChallengeService challenges;
    private final CredentialService credentials;
    private final AuthMailer mailer;
    private final IdentityProperties properties;

    /**
     * Unlike the passwordless flows this one needs no generic response: the caller is already
     * authenticated, so telling them their own address is already verified reveals nothing.
     */
    @Transactional
    public AckResponse request(UUID userId, String ipAddress) {
        IdentityUser user = credentials.requireActive(userId);
        if (user.isEmailVerified()) {
            throw ApiException.of(ErrorCode.EMAIL_ALREADY_VERIFIED, "That email is already verified");
        }

        ChallengeService.Raised raised = challenges.raise(
                ChallengePurpose.EMAIL_VERIFY, user.getId(), user.getEmail(), ipAddress);
        mailer.sendEmailVerification(
                user.getEmail(),
                user.effectiveDisplayName(),
                properties.urls().console() + "/verify-email?token="
                        + URLEncoder.encode(raised.rawSecret(), StandardCharsets.UTF_8),
                challenges.expiryMinutes());

        return new AckResponse("Check your inbox for a confirmation link.");
    }

    @Transactional
    public AckResponse confirm(String rawToken) {
        AuthChallenge challenge = challenges.consumeBySecret(rawToken, ChallengePurpose.EMAIL_VERIFY);
        if (challenge.getUserId() == null) {
            throw ApiException.of(ErrorCode.TOKEN_INVALID, "That link is not valid");
        }
        IdentityUser user = credentials.requireActive(challenge.getUserId());
        if (user.isEmailVerified()) {
            throw ApiException.of(ErrorCode.EMAIL_ALREADY_VERIFIED, "That email is already verified");
        }
        credentials.markEmailVerified(user.getId());
        return new AckResponse("Your email has been verified.");
    }
}
