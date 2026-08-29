package com.prabhix.identity.common;

import lombok.Getter;

/**
 * The only exception this service throws for an expected failure.
 *
 * <p>The {@link ErrorCode} values and their HTTP statuses are copied from the platform, because
 * clients already switch on those codes and moving auth behind a different origin must not also
 * change what a failed sign-in looks like on the wire.
 */
@Getter
public class ApiException extends RuntimeException {

    private final ErrorCode code;

    private ApiException(ErrorCode code, String message) {
        super(message);
        this.code = code;
    }

    public static ApiException of(ErrorCode code, String message) {
        return new ApiException(code, message);
    }

    public static ApiException notFound(String what) {
        return new ApiException(ErrorCode.NOT_FOUND, what + " was not found");
    }
}
