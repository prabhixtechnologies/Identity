package com.prabhix.identity.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.UUID;

/**
 * Fills in a product's local {@code users} row for someone identity knows about and the product
 * does not.
 *
 * <p>Products keep a thin mirror keyed by the identity {@code sub}, because their own tables foreign-key
 * to it — {@code created_by}, {@code assignee_id}, memberships — and those cannot point across a
 * service boundary. The bulk import seeds the mirror; this covers everyone who signs up afterwards,
 * on the first request that names them.
 */
public class IdentityUserMirror {

    private static final Logger log = LoggerFactory.getLogger(IdentityUserMirror.class);

    private final IdentityInternalClient identity;
    private final UserMirrorStore store;

    public IdentityUserMirror(IdentityInternalClient identity, UserMirrorStore store) {
        this.identity = identity;
        this.store = store;
    }

    /**
     * Creates or refreshes the mirror row for one identity subject.
     *
     * @return what identity said about them, already written
     * @throws IdentityClientException {@link IdentityClientException.Kind#NOT_FOUND} when identity
     *     signed a token for a subject it will not describe — deleted between issuing the token and
     *     this request, most likely — and {@link IdentityClientException.Kind#UNAVAILABLE} or
     *     {@link IdentityClientException.Kind#DISABLED} when it could not be asked
     */
    public IdentityUser pull(UUID subject) {
        List<IdentityUser> found = identity.lookup(List.of(subject), List.of());
        if (found.isEmpty()) {
            throw new IdentityClientException(IdentityClientException.Kind.NOT_FOUND,
                    "That account no longer exists");
        }
        IdentityUser user = found.getFirst();
        store.upsert(user);
        log.info("Mirrored identity user {}", subject);
        return user;
    }

    /**
     * Writes the mirror row from details the caller already holds, without asking identity for them.
     *
     * <p>For provisioning at signup, where identity is the caller and is waiting on the reply. Going
     * through {@link #pull} there would have the product call back into identity while identity holds
     * a thread waiting on the product — fine until enough signups arrive at once for both pools to be
     * full of requests waiting on each other.
     */
    public void mirrorFromSignup(UUID subject, String email, boolean emailVerified, String fullName) {
        store.upsert(IdentityUser.fromSignup(subject, email, emailVerified, fullName));
        log.info("Mirrored identity user {} at signup", subject);
    }
}
