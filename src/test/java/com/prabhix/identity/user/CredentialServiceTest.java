package com.prabhix.identity.user;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.config.IdentityProperties;
import com.prabhix.identity.config.TestProperties;
import com.prabhix.identity.event.AuthEventRecorder;
import com.prabhix.identity.token.TokenDenyList;
import com.prabhix.identity.user.IdentityUser.UserStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CredentialServiceTest {

    private static final String PASSWORD = "correct-horse-battery";

    private IdentityUserRepository users;
    private TokenDenyList denyList;
    private CredentialService service;

    @BeforeEach
    void setUp() {
        users = mock(IdentityUserRepository.class);
        denyList = mock(TokenDenyList.class);
        // Strength 4, the bcrypt minimum. Strength 12 is right in production and would add roughly a
        // quarter-second per hash here, which across these tests is most of the run time.
        PasswordEncoder encoder = new BCryptPasswordEncoder(4);
        IdentityProperties properties = TestProperties.signing("", List.of());
        service = new CredentialService(users, encoder, denyList, properties,
                mock(AuthEventRecorder.class), new LoginFailureWriter(users));
        when(users.save(any(IdentityUser.class))).thenAnswer(call -> call.getArgument(0));
        // Mockito stubs an interface's default methods like any other, which would skip the address
        // normalization they exist to perform. Calling through means the stubs below can be written
        // against normalized addresses, and a test may pass a mixed-case one to prove the folding.
        when(users.findActiveByEmail(anyString())).thenCallRealMethod();
        when(users.activeEmailExists(anyString())).thenCallRealMethod();
    }

    private IdentityUser existing(String rawPassword) {
        IdentityUser user = new IdentityUser();
        user.setId(UUID.randomUUID());
        user.setEmail("owner@example.com");
        user.setFullName("Demo Owner");
        if (rawPassword != null) {
            user.setPasswordHash(new BCryptPasswordEncoder(4).encode(rawPassword));
        }
        when(users.findByEmailAndDeletedAtIsNull("owner@example.com")).thenReturn(Optional.of(user));
        when(users.findByIdAndDeletedAtIsNull(user.getId())).thenReturn(Optional.of(user));
        return user;
    }

    @Test
    @DisplayName("an unknown address and a wrong password fail identically")
    void unknownAddressLooksLikeAWrongPassword() {
        existing(PASSWORD);
        when(users.findByEmailAndDeletedAtIsNull("stranger@example.com")).thenReturn(Optional.empty());

        ApiException unknown = catchApi(() -> service.authenticate("stranger@example.com", PASSWORD));
        ApiException wrong = catchApi(() -> service.authenticate("owner@example.com", "not-the-password"));

        // Anything else makes this endpoint a membership oracle: ask it about an address and learn
        // whether that person has an account.
        assertThat(unknown.getCode()).isEqualTo(ErrorCode.INVALID_CREDENTIALS);
        assertThat(wrong.getCode()).isEqualTo(ErrorCode.INVALID_CREDENTIALS);
        assertThat(unknown.getMessage()).isEqualTo(wrong.getMessage());
    }

    @Test
    @DisplayName("locks the account on the configured number of failures, and not before")
    void locksAfterConfiguredFailures() {
        IdentityUser user = existing(PASSWORD);

        for (int attempt = 1; attempt < 5; attempt++) {
            catchApi(() -> service.authenticate("owner@example.com", "wrong"));
            assertThat(user.getStatus()).isEqualTo(UserStatus.ACTIVE);
            assertThat(user.isLockedNow()).isFalse();
        }

        catchApi(() -> service.authenticate("owner@example.com", "wrong"));

        assertThat(user.getStatus()).isEqualTo(UserStatus.LOCKED);
        assertThat(user.getLockedUntil()).isAfter(Instant.now().plusSeconds(14 * 60));
    }

    @Test
    @DisplayName("a locked account is refused without the password being checked")
    void lockedAccountIsRefusedFirst() {
        IdentityUser user = existing(PASSWORD);
        user.setLockedUntil(Instant.now().plusSeconds(600));
        user.setStatus(UserStatus.LOCKED);

        ApiException ex = catchApi(() -> service.authenticate("owner@example.com", PASSWORD));

        // Order matters: checking the password first would let a lockout be extended indefinitely by
        // an attacker, and would tell them when they had guessed right.
        assertThat(ex.getCode()).isEqualTo(ErrorCode.ACCOUNT_LOCKED);
        assertThat(user.getFailedLoginAttempts()).isZero();
    }

    @Test
    @DisplayName("a disabled account cannot sign in even with the right password")
    void disabledAccountIsRefused() {
        IdentityUser user = existing(PASSWORD);
        user.setStatus(UserStatus.DISABLED);

        assertThat(catchApi(() -> service.authenticate("owner@example.com", PASSWORD)).getCode())
                .isEqualTo(ErrorCode.ACCOUNT_DISABLED);
    }

    @Test
    @DisplayName("an account with no password cannot be signed into with one")
    void passwordlessAccountRejectsAnyPassword() {
        existing(null);

        // The failure this prevents: bcrypt's matches() against a null hash, and any code path where
        // "no password set" could be read as "any password accepted".
        assertThat(catchApi(() -> service.authenticate("owner@example.com", "anything")).getCode())
                .isEqualTo(ErrorCode.INVALID_CREDENTIALS);
    }

    @Test
    @DisplayName("a successful sign-in clears the failure counter and the lock")
    void successResetsFailures() {
        IdentityUser user = existing(PASSWORD);
        user.setFailedLoginAttempts(3);

        service.authenticate("owner@example.com", PASSWORD);

        assertThat(user.getFailedLoginAttempts()).isZero();
        assertThat(user.getLockedUntil()).isNull();
        assertThat(user.getLastLoginAt()).isNotNull();
    }

    @Test
    @DisplayName("setting a password revokes tokens issued before it")
    void setPasswordRevokesEverythingOlder() {
        IdentityUser user = existing(PASSWORD);

        service.setPassword(user.getId(), "a-brand-new-password");

        assertThat(user.getPasswordChangedAt()).isNotNull();
        // Without this, a stolen access token keeps working for its full 15 minutes after the victim
        // has already changed their password in response to the theft.
        verify(denyList).revokeUser(user.getId());
    }

    @Test
    @DisplayName("a password shorter than the minimum is refused before anything is written")
    void refusesWeakPassword() {
        when(users.existsByEmailAndDeletedAtIsNull(anyString())).thenReturn(false);

        assertThat(catchApi(() -> service.create("new@example.com", "short", "New Person")).getCode())
                .isEqualTo(ErrorCode.VALIDATION_FAILED);
        verify(users, never()).save(any(IdentityUser.class));
    }

    @Test
    @DisplayName("registering an address that already has an account is a conflict")
    void refusesDuplicateEmail() {
        when(users.existsByEmailAndDeletedAtIsNull("owner@example.com")).thenReturn(true);

        assertThat(catchApi(() -> service.create("Owner@Example.com ", PASSWORD, "Someone")).getCode())
                .isEqualTo(ErrorCode.ALREADY_EXISTS);
    }

    @Test
    @DisplayName("email is stored lowercased and trimmed")
    void normalisesEmail() {
        when(users.existsByEmailAndDeletedAtIsNull("owner@example.com")).thenReturn(false);

        IdentityUser created = service.create("  Owner@Example.COM  ", PASSWORD, " Demo Owner ");

        assertThat(created.getEmail()).isEqualTo("owner@example.com");
        assertThat(created.getFullName()).isEqualTo("Demo Owner");
    }

    @Test
    @DisplayName("marking email verified twice does not move the timestamp")
    void verificationIsIdempotent() {
        IdentityUser user = existing(PASSWORD);

        service.markEmailVerified(user.getId());
        Instant first = user.getEmailVerifiedAt();
        service.markEmailVerified(user.getId());

        assertThat(user.getEmailVerifiedAt()).isEqualTo(first);
    }

    /** Runs the action and returns the {@link ApiException} it must throw. */
    private ApiException catchApi(Runnable action) {
        try {
            action.run();
        } catch (ApiException ex) {
            return ex;
        }
        throw new AssertionError("Expected an ApiException, but the call succeeded");
    }

    @Test
    @DisplayName("looking up an account that does not exist is a 404, not a null")
    void requireActiveThrows() {
        UUID missing = UUID.randomUUID();
        when(users.findByIdAndDeletedAtIsNull(missing)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.requireActive(missing))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("was not found");
    }
}
