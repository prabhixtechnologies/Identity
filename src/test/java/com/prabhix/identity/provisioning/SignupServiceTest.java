package com.prabhix.identity.provisioning;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.user.CredentialService;
import com.prabhix.identity.user.IdentityUser;
import com.prabhix.identity.user.IdentityUserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Signing up is two records in two databases, and this is where "both or neither" is enforced.
 *
 * <p>The interesting case is the failure. A signup that creates the account and not the organization
 * leaves somebody who can sign in, is shown nothing, and cannot start again — their address is taken
 * by the account that does not work. That state is unreachable from a support conversation: the only
 * fix is in two databases at once.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SignupServiceTest {

    @Mock private CredentialService credentials;
    @Mock private PlatformProvisioning platform;
    @Mock private IdentityUserRepository users;

    private SignupService signup;

    private IdentityUser account;

    @BeforeEach
    void setUp() {
        signup = new SignupService(credentials, platform, users);

        account = new IdentityUser();
        account.setId(UUID.randomUUID());
        account.setEmail("someone@example.com");
        account.setFullName("Someone");

        when(credentials.create(any(), any(), any())).thenReturn(account);
        when(platform.configured()).thenReturn(true);
    }

    @Test
    void accountWithoutAWorkspaceSkipsThePlatform() {
        assertSame(account, signup.signUp("someone@example.com", "long-enough-password", "Someone", " "));

        verify(credentials).create("someone@example.com", "long-enough-password", "Someone");
        verify(platform, never()).createOrganization(any(), any());
    }

    @Test
    void createsTheAccountAndItsWorkspace() {
        when(platform.createOrganization(account, "Acme")).thenReturn(UUID.randomUUID());

        assertSame(account, signup.signUp("someone@example.com", "long-enough-password", "Someone", "Acme"));

        verify(credentials).create("someone@example.com", "long-enough-password", "Someone");
        verify(platform).createOrganization(account, "Acme");
        // Nothing withdrawn on the happy path, which is the other half of the guarantee.
        verify(users, never()).save(any());
    }

    @Test
    void withdrawsTheAccountWhenTheWorkspaceCannotBeCreated() {
        doThrow(ApiException.of(ErrorCode.INTERNAL_ERROR, "platform is down"))
                .when(platform).createOrganization(eq(account), any());

        assertThrows(ApiException.class,
                () -> signup.signUp("someone@example.com", "long-enough-password", "Someone", "Acme"));

        ArgumentCaptor<IdentityUser> saved = ArgumentCaptor.forClass(IdentityUser.class);
        verify(users).save(saved.capture());
        // Soft-deleted, not removed: the address is free for another attempt and the failure is still
        // countable afterwards. A hard delete would leave nothing to count.
        assertNotNull(saved.getValue().getDeletedAt(),
                "the account must be withdrawn, or the address is taken by an account that cannot be used");
    }

    @Test
    void reportsWhyTheSignupFailedRatherThanWhyTheCleanupDid() {
        // Whoever is signing up can act on "try again"; they can do nothing about a failed cleanup, and
        // replacing the message would hide the one thing they need to know.
        doThrow(ApiException.of(ErrorCode.INTERNAL_ERROR, "workspace could not be created"))
                .when(platform).createOrganization(eq(account), any());
        when(users.save(any())).thenThrow(new IllegalStateException("database gone too"));

        ApiException thrown = assertThrows(ApiException.class,
                () -> signup.signUp("someone@example.com", "long-enough-password", "Someone", "Acme"));

        assertSame(ErrorCode.INTERNAL_ERROR, thrown.getCode());
    }

    @Test
    void doesNotTouchTheAccountWhenTheAddressIsAlreadyTaken() {
        // The account was never created, so there is nothing to withdraw. Withdrawing here would mean
        // soft-deleting somebody else's existing account because a stranger guessed their address.
        when(credentials.create(any(), any(), any()))
                .thenThrow(ApiException.of(ErrorCode.ALREADY_EXISTS, "An account already uses that email"));

        assertThrows(ApiException.class,
                () -> signup.signUp("someone@example.com", "long-enough-password", "Someone", "Acme"));

        verify(users, never()).save(any());
        verify(platform, never()).createOrganization(any(), any());
    }

    @Test
    void offersSignupOnlyWhereThereIsAPlatformToProvisionAgainst() {
        // The page reads this to decide whether to show the form at all. Showing it without a platform
        // would take a password, create an account, and withdraw it a moment later.
        assertTrue(signup.available());

        when(platform.configured()).thenReturn(false);
        assertFalse(signup.available());
    }
}
