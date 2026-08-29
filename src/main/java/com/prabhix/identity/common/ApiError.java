package com.prabhix.identity.common;

import java.time.Instant;
import java.util.Map;

/**
 * The error body shape, identical to the platform's so a client cannot tell which service answered.
 *
 * @param code        stable machine-readable {@link ErrorCode} name
 * @param message     human-readable, safe to show a user
 * @param fieldErrors field name to message, for form validation failures
 * @param traceId     correlates this response with server logs
 * @param path        request path that failed
 * @param timestamp   server time the error was produced
 */
public record ApiError(
        String code,
        String message,
        Map<String, String> fieldErrors,
        String traceId,
        String path,
        Instant timestamp) {

    public static ApiError of(ErrorCode code, String message, String traceId, String path) {
        return new ApiError(code.name(), message, null, traceId, path, Instant.now());
    }

    public static ApiError of(ErrorCode code,
                              String message,
                              Map<String, String> fieldErrors,
                              String traceId,
                              String path) {
        Map<String, String> fields = (fieldErrors == null || fieldErrors.isEmpty()) ? null : fieldErrors;
        return new ApiError(code.name(), message, fields, traceId, path, Instant.now());
    }
}
