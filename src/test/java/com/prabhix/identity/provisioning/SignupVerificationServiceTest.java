package com.prabhix.identity.provisioning;

import com.prabhix.identity.challenge.AuthChallenge;
import com.prabhix.identity.challenge.ChallengeService;
import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.mail.AuthMailer;
import com.prabhix.identity.user.CredentialService;
import com.prabhix.identity.user.IdentityUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.UUID;

import static com.prabhix.identity.challenge.AuthChallenge.ChallengePurpose.EMAIL_OTP;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SignupVerificationServiceTest {

    @Mock private ChallengeService challenges;
    @Mock private CredentialService credentials;
    @Mock private AuthMailer mailer;

    private SignupVerificationService service;
    private IdentityUser user;

    @BeforeEach
    void setUp() {
        service = new SignupVerificationService(challenges, credentials, mailer);
        user = new IdentityUser();
        user.setId(UUID.randomUUID());
        user.setEmail("owner@example.com");
        user.setFullName("Owner");
    }

    @Test
    void sendsANumericSignupCode() {
        AuthChallenge row = new AuthChallenge();
        when(challenges.raise(EMAIL_OTP, user.getId(), user.getEmail(), "127.0.0.1"))
                .thenReturn(new ChallengeService.Raised(row, "123456"));
        when(challenges.expiryMinutes()).thenReturn(10L);

        service.send(user, "127.0.0.1");

        verify(mailer).sendSignupOtp("owner@example.com", "Owner", "123456", 10);
    }

    @Test
    void matchingCodeVerifiesTheAddress() {
        AuthChallenge row = new AuthChallenge();
        row.setUserId(user.getId());
        when(challenges.consumeByCode("owner@example.com", "123456", EMAIL_OTP)).thenReturn(row);
        when(credentials.requireSignInAllowed(user.getId())).thenReturn(user);

        service.verify(user.getId(), "owner@example.com", "123456");

        verify(credentials).markEmailVerified(user.getId());
    }

    @Test
    void codeForAnotherPendingAccountIsRefused() {
        AuthChallenge row = new AuthChallenge();
        row.setUserId(UUID.randomUUID());
        when(challenges.consumeByCode("owner@example.com", "123456", EMAIL_OTP)).thenReturn(row);

        assertThatThrownBy(() -> service.verify(user.getId(), "owner@example.com", "123456"))
                .isInstanceOf(ApiException.class);
    }
}
