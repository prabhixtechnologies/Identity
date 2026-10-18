package com.prabhix.identity.provisioning;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.config.IdentityProperties;
import com.prabhix.identity.config.TestProperties;
import com.prabhix.identity.mail.AuthMailer;
import com.prabhix.identity.provisioning.PendingSignupStore.Draft;
import com.prabhix.identity.provisioning.PendingSignupStore.Issued;
import com.prabhix.identity.user.CredentialService;
import com.prabhix.identity.user.IdentityUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SignupVerificationServiceTest {

    @Mock private PendingSignupStore pending;
    @Mock private CredentialService credentials;
    @Mock private SignupService signup;
    @Mock private AuthMailer mailer;

    private SignupVerificationService service;

    @BeforeEach
    void setUp() {
        IdentityProperties properties = TestProperties.signing("", List.of());
        service = new SignupVerificationService(pending, credentials, signup, mailer, properties);
    }

    @Test
    void beginSendsTheCodeAndDoesNotInsertAnAccount() {
        when(credentials.hashPassword("long-enough-password")).thenReturn("$hash");
        when(pending.begin("owner@example.com", "Owner", "Acme", "$hash"))
                .thenReturn(new Issued("token", "owner@example.com", "Owner", "123456"));

        String token = service.begin("owner@example.com", "long-enough-password", "Owner", "Acme");

        assertThat(token).isEqualTo("token");
        verify(mailer).sendSignupOtp("owner@example.com", "Owner", "123456", 10L);
        verify(credentials, never()).createVerified(any(), any(), any());
        verify(signup, never()).provision(any(), any());
    }

    @Test
    void aTakenAddressIsRefusedBeforeAnythingIsHeld() {
        doThrow(ApiException.of(ErrorCode.ALREADY_EXISTS, "An account already uses that email"))
                .when(credentials).requireEmailAvailable("owner@example.com");

        assertThatThrownBy(() -> service.begin("owner@example.com", "long-enough-password", "Owner", "Acme"))
                .isInstanceOf(ApiException.class);

        verify(pending, never()).begin(any(), any(), any(), any());
        verify(mailer, never()).sendSignupOtp(any(), any(), any(), eq(10L));
    }

    @Test
    void mailFailureDropsTheHold() {
        when(credentials.hashPassword("long-enough-password")).thenReturn("$hash");
        when(pending.begin(any(), any(), any(), any()))
                .thenReturn(new Issued("token", "owner@example.com", "Owner", "123456"));
        doThrow(ApiException.of(ErrorCode.DEPENDENCY_UNAVAILABLE, "mail down"))
                .when(mailer).sendSignupOtp(any(), any(), any(), eq(10L));

        assertThatThrownBy(() -> service.begin("owner@example.com", "long-enough-password", "Owner", null))
                .isInstanceOf(ApiException.class);

        verify(pending).discard("token");
        verify(credentials, never()).createVerified(any(), any(), any());
    }

    @Test
    void matchingCodeCreatesTheAccountAndThenTheWorkspace() {
        Draft draft = new Draft("owner@example.com", "Owner", "Acme", "$hash", "otp", 0, 0);
        when(pending.match("token", "123456")).thenReturn(draft);
        IdentityUser user = new IdentityUser();
        when(credentials.createVerified("owner@example.com", "$hash", "Owner")).thenReturn(user);
        when(signup.provision(user, "Acme")).thenReturn(user);

        assertThat(service.confirm("token", "123456")).isSameAs(user);

        verify(pending).discard("token");
    }

    @Test
    void resendSendsANewCodeWithoutCreatingAnAccount() {
        when(pending.resend("token")).thenReturn(new Issued("token", "owner@example.com", "Owner", "654321"));

        service.resend("token");

        verify(mailer).sendSignupOtp("owner@example.com", "Owner", "654321", 10L);
        verify(credentials, never()).createVerified(any(), any(), any());
    }
}
