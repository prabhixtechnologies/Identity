package com.prabhix.identity.client;

/** A call to identity's internal API did not do what was asked. */
public class IdentityClientException extends RuntimeException {

    public enum Kind {
        /** No internal URL or service token is configured; the call was never attempted. */
        DISABLED,
        /** Identity could not be reached, or answered 5xx. Safe to retry. */
        UNAVAILABLE,
        /** Identity does not know the user, client or key that was named. */
        NOT_FOUND,
        /** Identity understood the call and refused it: bad token, bad input, forbidden action. */
        REJECTED
    }

    private final Kind kind;

    public IdentityClientException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }

    public IdentityClientException(Kind kind, String message, Throwable cause) {
        super(message, cause);
        this.kind = kind;
    }

    public Kind kind() {
        return kind;
    }
}
