package com.prabhix.identity.client;

import java.time.Instant;
import java.util.UUID;

/**
 * The shape identity describes a user in, for products to mirror.
 *
 * <p>{@code platformAdmin} is carried because identity's schema still has the column from the bulk
 * import. No product may read it as authority: staff roles are granted in the oneOps database and
 * nowhere else, so a compromised identity service cannot elevate itself in a product.
 */
public record IdentityUser(UUID id,
                           String email,
                           boolean emailVerified,
                           String fullName,
                           String displayName,
                           String avatarUrl,
                           String jobTitle,
                           String timezone,
                           String locale,
                           String status,
                           boolean platformAdmin,
                           Instant updatedAt) {

    /** A minimal description from the signup hook, before the person has filled anything in. */
    public static IdentityUser fromSignup(UUID id, String email, boolean emailVerified, String fullName) {
        return new IdentityUser(id, email, emailVerified, fullName,
                null, null, null, null, null, "ACTIVE", false, Instant.now());
    }

    public boolean isActive() {
        return status == null || "ACTIVE".equalsIgnoreCase(status);
    }
}
