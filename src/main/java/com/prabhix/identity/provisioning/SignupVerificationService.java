package com.prabhix.identity.provisioning;

import com.prabhix.identity.challenge.AuthChallenge;
import com.prabhix.identity.challenge.AuthChallenge.ChallengePurpose;
import com.prabhix.identity.challenge.ChallengeService;
import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.mail.AuthMailer;
import com.prabhix.identity.user.CredentialService;
import com.prabhix.identity.user.IdentityUser;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/** Email ownership gate between creating credentials and activating a signup session. */
@Service
@RequiredArgsConstructor
public class SignupVerificationService {

    private final ChallengeService challenges;
    private final CredentialService credentials;
    private final AuthMailer mailer;

    @Transactional
    public void send(IdentityUser user, String ipAddress) {
        ChallengeService.Raised raised = challenges.raise(
                ChallengePurpose.EMAIL_OTP, user.getId(), user.getEmail(), ipAddress);
        mailer.sendSignupOtp(
                user.getEmail(), user.effectiveDisplayName(), raised.rawSecret(), challenges.expiryMinutes());
    }

    @Transactional
    public void resend(UUID userId, String ipAddress) {
        send(credentials.requireActive(userId), ipAddress);
    }

    @Transactional
    public IdentityUser verify(UUID expectedUserId, String email, String code) {
        AuthChallenge challenge = challenges.consumeByCode(email, code, ChallengePurpose.EMAIL_OTP);
        if (expectedUserId == null || !expectedUserId.equals(challenge.getUserId())) {
            throw ApiException.of(ErrorCode.OTP_INVALID, "That code is not correct");
        }
        credentials.markEmailVerified(expectedUserId);
        return credentials.requireSignInAllowed(expectedUserId);
    }
}
