package com.prabhix.identity.provisioning;

import com.prabhix.identity.user.CredentialService;
import com.prabhix.identity.user.IdentityUser;
import com.prabhix.identity.user.IdentityUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;

/**
 * Self-serve signup, which is two records in two databases and has to be all or nothing.
 *
 * <p>An account lives here and an organization lives in the platform, and half a signup is worse than
 * none. An account without an organization can sign in and is shown a console with nothing in it and
 * no way to fix that; and the person cannot start again, because their address is now taken by the
 * account that does not work. So when the platform will not provision, the account is withdrawn.
 *
 * <p>Withdrawn rather than removed: the row is soft-deleted, which frees the address for another
 * attempt while leaving evidence that an attempt happened. A failure here is a two-service outage
 * worth being able to count afterwards, and a hard delete would leave nothing to count.
 *
 * <p>Two transactions rather than one, necessarily. The organization is created over HTTP, and a
 * transaction cannot span that — holding one open across a network call would also mean holding a
 * database connection for the duration of somebody else's request, which is how a slow neighbour
 * becomes an outage here. The compensation below is the price of that, and is deliberate.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SignupService {

    private final CredentialService credentials;
    private final PlatformProvisioning platform;
    private final IdentityUserRepository users;

    /** Whether a signup form should offer to create a workspace at all. */
    public boolean available() {
        return platform.configured();
    }

    /**
     * Creates the account and its organization, or neither.
     *
     * @param organizationName what to call the OneOps workspace. Blank skips that call. MobiStack
     *     uses the blank form: the shop is created in MobiStack after the account exists.
     */
    public IdentityUser signUp(String email, String password, String fullName, String organizationName) {
        IdentityUser user = credentials.create(email, password, fullName);
        // MobiStack creates the shop after this account exists. A workspace name here would open an
        // OneOps organization, which is neither that shop nor the fitment group.
        if (organizationName == null || organizationName.isBlank()) {
            return user;
        }
        try {
            platform.createOrganization(user, organizationName.trim());
        } catch (RuntimeException ex) {
            withdraw(user);
            throw ex;
        }
        return user;
    }

    /**
     * Undoes an account whose organization could not be created.
     *
     * <p>Swallows its own failure and logs loudly. The caller is already throwing the reason the
     * signup failed, and replacing that with "and the cleanup also failed" would tell whoever is
     * signing up something they can do nothing about, while hiding the message that tells them their
     * address is free to try again. The orphan is recorded here instead, which is where somebody
     * looking for it would look.
     */
    private void withdraw(IdentityUser user) {
        try {
            user.setDeletedAt(Instant.now());
            users.save(user);
            log.warn("Withdrew account {} because its organization could not be created", user.getId());
        } catch (RuntimeException cleanupFailure) {
            log.error("ORPHANED ACCOUNT {} ({}): its organization was not created and the account "
                            + "could not be withdrawn. The address is now taken by an account that "
                            + "cannot be used.",
                    user.getId(), user.getEmail(), cleanupFailure);
        }
    }
}
