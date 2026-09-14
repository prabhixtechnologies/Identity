package com.prabhix.identity.user;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Persists a failed sign-in attempt in a transaction that survives the sign-in's own.
 *
 * <p>{@code CredentialService.authenticate} counts the failure and then throws, and the exception
 * rolls back the transaction it runs in — which, without this, took the count with it. Five wrong
 * passwords left {@code failed_login_attempts} at zero and the lockout never engaged. Writing the
 * counter through {@code REQUIRES_NEW} commits it before the exception is thrown, so the attempt is
 * remembered whatever happens to the request that made it.
 *
 * <p>A separate bean because {@code @Transactional} only applies through the proxy, and a method on
 * {@code CredentialService} calling another method on itself would not go through one.
 */
@Component
@RequiredArgsConstructor
class LoginFailureWriter {

    private final IdentityUserRepository users;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void save(IdentityUser user) {
        users.save(user);
    }
}
