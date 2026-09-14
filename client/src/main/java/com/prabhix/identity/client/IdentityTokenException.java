package com.prabhix.identity.client;

/**
 * Why a bearer token was refused.
 *
 * <p>Products translate the {@link Reason} into their own error vocabulary and response shape; the
 * message here is safe to show to a caller.
 */
public class IdentityTokenException extends RuntimeException {

    public enum Reason {
        /** Signature and issuer were fine; {@code exp} has passed. */
        EXPIRED,
        /** Malformed, wrong algorithm, unknown key, wrong issuer, or a bad signature. */
        INVALID,
        /** This deployment has no issuer configured, so no token can be trusted. */
        UNTRUSTED
    }

    private final Reason reason;

    public IdentityTokenException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public IdentityTokenException(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }
}
