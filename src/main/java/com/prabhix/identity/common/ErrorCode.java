package com.prabhix.identity.common;

import org.springframework.http.HttpStatus;

/**
 * Machine-readable error codes, spelled exactly as the platform spells them.
 *
 * <p>Only the auth-relevant subset is here. Clients switch on {@code code} and never on the
 * message, so these names are public contract: the console's sign-in screen already distinguishes
 * {@code ACCOUNT_LOCKED} from {@code INVALID_CREDENTIALS}, and renaming one breaks that.
 */
public enum ErrorCode {

    UNAUTHENTICATED(HttpStatus.UNAUTHORIZED),
    INVALID_CREDENTIALS(HttpStatus.UNAUTHORIZED),
    TOKEN_EXPIRED(HttpStatus.UNAUTHORIZED),
    TOKEN_INVALID(HttpStatus.UNAUTHORIZED),
    TOKEN_REVOKED(HttpStatus.UNAUTHORIZED),
    FORBIDDEN(HttpStatus.FORBIDDEN),
    ACCOUNT_LOCKED(HttpStatus.FORBIDDEN),
    ACCOUNT_DISABLED(HttpStatus.FORBIDDEN),
    EMAIL_NOT_VERIFIED(HttpStatus.FORBIDDEN),
    OTP_INVALID(HttpStatus.BAD_REQUEST),
    OTP_EXPIRED(HttpStatus.BAD_REQUEST),
    OTP_ATTEMPTS_EXCEEDED(HttpStatus.TOO_MANY_REQUESTS),
    EMAIL_ALREADY_VERIFIED(HttpStatus.CONFLICT),

    VALIDATION_FAILED(HttpStatus.BAD_REQUEST),
    MALFORMED_REQUEST(HttpStatus.BAD_REQUEST),

    NOT_FOUND(HttpStatus.NOT_FOUND),
    ALREADY_EXISTS(HttpStatus.CONFLICT),
    CONFLICT(HttpStatus.CONFLICT),

    RATE_LIMITED(HttpStatus.TOO_MANY_REQUESTS),
    FEATURE_DISABLED(HttpStatus.FORBIDDEN),
    DEPENDENCY_UNAVAILABLE(HttpStatus.SERVICE_UNAVAILABLE),
    INTERNAL_ERROR(HttpStatus.INTERNAL_SERVER_ERROR);

    private final HttpStatus status;

    ErrorCode(HttpStatus status) {
        this.status = status;
    }

    public HttpStatus status() {
        return status;
    }
}
