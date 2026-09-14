package com.prabhix.identity.client;

/**
 * Where a product writes its local copy of an identity user.
 *
 * <p>Each product has its own {@code users} table with its own columns and its own defaults, so the
 * SQL stays with the product. What is shared is everything around it: asking identity, deciding that
 * an unknown subject is a refusal, and the signup hook that writes without asking. Implement this as
 * a bean and {@link IdentityUserMirror} is auto-configured on top of it.
 *
 * <p>Implementations should write with an upsert keyed by {@link IdentityUser#id()} and must keep
 * identity's id as the primary key. Hibernate's generated identifiers would replace an assigned one,
 * which is why the reference implementations use plain SQL.
 */
@FunctionalInterface
public interface UserMirrorStore {

    void upsert(IdentityUser user);
}
