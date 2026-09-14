package com.prabhix.identity.account;

import com.prabhix.identity.challenge.AuthChallenge;
import com.prabhix.identity.challenge.AuthChallenge.ChallengePurpose;
import com.prabhix.identity.challenge.ChallengeService;
import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.config.TestProperties;
import com.prabhix.identity.event.AuthEventRecorder;
import com.prabhix.identity.event.AuthEventType;
import com.prabhix.identity.mail.AuthMailer;
import com.prabhix.identity.user.AuthIdentity;
import com.prabhix.identity.user.AuthIdentity.AuthProvider;
import com.prabhix.identity.user.AuthIdentityRepository;
import com.prabhix.identity.user.CredentialService;
import com.prabhix.identity.user.IdentityUser;
import com.prabhix.identity.user.IdentityUserRepository;
import com.prabhix.identity.webauthn.WebAuthnCredentialRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AccountServiceTest {

    private CredentialService credentials;
    private IdentityUserRepository users;
    private AuthIdentityRepository identities;
    private WebAuthnCredentialRepository passkeys;
    private ChallengeService challenges;
    private AuthEventRecorder events;
    private AccountService accounts;

    @BeforeEach
    void setUp() {
        credentials = mock(CredentialService.class);
        users = mock(IdentityUserRepository.class);
        identities = mock(AuthIdentityRepository.class);
        passkeys = mock(WebAuthnCredentialRepository.class);
        challenges = mock(ChallengeService.class);
        events = mock(AuthEventRecorder.class);
        accounts = new AccountService(
                credentials, users, identities, passkeys, challenges,
                mock(AuthMailer.class), TestProperties.signing("", List.of()), events);
        when(users.save(any(IdentityUser.class))).thenAnswer(call -> call.getArgument(0));
    }

    private IdentityUser userWithPassword() {
        IdentityUser user = new IdentityUser();
        user.setId(UUID.randomUUID());
        user.setEmail("owner@example.com");
        user.setFullName("Demo Owner");
        user.setPasswordHash("not-a-real-hash");
        when(credentials.requireActive(user.getId())).thenReturn(user);
        when(credentials.requireSignInAllowed(user.getId())).thenReturn(user);
        return user;
    }

    @Test
    @DisplayName("a wrong current password is refused without changing anything")
    void wrongCurrentPasswordIsRefused() {
        IdentityUser user = userWithPassword();
        when(credentials.matchesPassword(user, "not-the-password")).thenReturn(false);

        assertThat(catchApi(() -> accounts.changePassword(user.getId(), "not-the-password",
                "a-brand-new-password")).getCode())
                .isEqualTo(ErrorCode.PASSWORD_INCORRECT);

        // Not a sign-in failure: incrementing the lockout counter from the account page would lock
        // the person out of the only session they have left to recover with.
        verify(credentials, never()).replacePassword(any(), any());
    }

    @Test
    @DisplayName("changing the password keeps the current session")
    void changePasswordDoesNotRevoke() {
        IdentityUser user = userWithPassword();
        when(credentials.matchesPassword(user, "correct-horse-battery")).thenReturn(true);

        accounts.changePassword(user.getId(), "correct-horse-battery", "a-brand-new-password");

        verify(credentials).replacePassword(user, "a-brand-new-password");
        verify(events).success(eq(AuthEventType.PASSWORD_CHANGED), eq(user.getId()),
                eq(user.getEmail()), any());
        // replacePassword, not setPassword: the latter writes a deny-list entry that would bounce
        // the token the caller is still using.
        verify(credentials, never()).setPassword(any(), any());
    }

    @Test
    @DisplayName("unlinking Google is refused when it is the only remaining factor")
    void googleUnlinkRefusedWhenLastFactor() {
        IdentityUser user = new IdentityUser();
        user.setId(UUID.randomUUID());
        user.setEmail("google-only@example.com");
        user.setFullName("Google Only");
        when(credentials.requireSignInAllowed(user.getId())).thenReturn(user);

        AuthIdentity google = new AuthIdentity();
        google.setUserId(user.getId());
        google.setProvider(AuthProvider.GOOGLE);
        google.setProviderSubject("sub-1");
        when(identities.findByUserIdAndProvider(user.getId(), AuthProvider.GOOGLE))
                .thenReturn(Optional.of(google));
        when(identities.existsByUserIdAndProvider(user.getId(), AuthProvider.GOOGLE)).thenReturn(true);
        when(passkeys.countByUserId(user.getId())).thenReturn(0L);

        assertThat(catchApi(() -> accounts.unlinkGoogle(user.getId())).getCode())
                .isEqualTo(ErrorCode.LAST_CREDENTIAL);
        verify(identities, never()).delete(any());
    }

    @Test
    @DisplayName("confirming an email-change link updates the address and marks it verified")
    void emailChangeConfirmUpdatesAddress() {
        IdentityUser user = userWithPassword();
        AuthChallenge challenge = new AuthChallenge();
        challenge.setUserId(user.getId());
        challenge.setPurpose(ChallengePurpose.EMAIL_CHANGE);
        challenge.setDestination("new@example.com");
        challenge.setConsumedAt(Instant.now());
        when(challenges.consumeBySecret("the-token", ChallengePurpose.EMAIL_CHANGE)).thenReturn(challenge);
        when(users.activeEmailExists("new@example.com")).thenReturn(false);

        accounts.confirmEmailChange("the-token");

        assertThat(user.getEmail()).isEqualTo("new@example.com");
        assertThat(user.getEmailVerifiedAt()).isNotNull();
        verify(events).success(eq(AuthEventType.EMAIL_CHANGED), eq(user.getId()),
                eq("new@example.com"), any());
    }

    private ApiException catchApi(Runnable action) {
        try {
            action.run();
        } catch (ApiException ex) {
            return ex;
        }
        throw new AssertionError("Expected an ApiException, but the call succeeded");
    }
}
