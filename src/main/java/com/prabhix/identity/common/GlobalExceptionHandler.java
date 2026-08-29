package com.prabhix.identity.common;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Translates every exception into an {@link ApiError}, matching the platform's handler.
 *
 * <p>Unexpected exceptions become a generic {@code INTERNAL_ERROR} carrying a trace id: the caller
 * gets something to quote in a support request, and nothing about our internals leaks. That matters
 * more here than elsewhere, because the exceptions this service throws are about credentials.
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ApiError> handleApi(ApiException ex, HttpServletRequest request) {
        String traceId = traceId();
        HttpStatus status = ex.getCode().status();

        // 5xx means we did something wrong, so keep the stack trace. 4xx is the caller's problem,
        // and at sign-in volumes logging every wrong password at error level buries everything else.
        if (status.is5xxServerError()) {
            log.error("[{}] {} at {}", traceId, ex.getCode(), request.getRequestURI(), ex);
        } else {
            log.debug("[{}] {} at {}: {}", traceId, ex.getCode(), request.getRequestURI(), ex.getMessage());
        }

        return ResponseEntity.status(status)
                .body(ApiError.of(ex.getCode(), ex.getMessage(), traceId, request.getRequestURI()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> handleBeanValidation(MethodArgumentNotValidException ex,
                                                        HttpServletRequest request) {
        Map<String, String> fields = new LinkedHashMap<>();
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            fields.putIfAbsent(error.getField(),
                    error.getDefaultMessage() == null ? "is invalid" : error.getDefaultMessage());
        }
        return ResponseEntity.status(ErrorCode.VALIDATION_FAILED.status())
                .body(ApiError.of(ErrorCode.VALIDATION_FAILED, "Some fields need attention",
                        fields, traceId(), request.getRequestURI()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiError> handleUnreadable(HttpMessageNotReadableException ex,
                                                    HttpServletRequest request) {
        return ResponseEntity.status(ErrorCode.MALFORMED_REQUEST.status())
                .body(ApiError.of(ErrorCode.MALFORMED_REQUEST, "That request body could not be read",
                        traceId(), request.getRequestURI()));
    }

    /**
     * Almost always the unique index on {@code users.email} or on a provider subject, both of which
     * are races between two concurrent sign-ups rather than anything the caller did wrong.
     */
    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ApiError> handleConflict(DataIntegrityViolationException ex,
                                                  HttpServletRequest request) {
        String traceId = traceId();
        log.warn("[{}] Constraint violation at {}: {}", traceId, request.getRequestURI(),
                ex.getMostSpecificCause().getMessage());
        return ResponseEntity.status(ErrorCode.CONFLICT.status())
                .body(ApiError.of(ErrorCode.CONFLICT, "That conflicts with something that already exists",
                        traceId, request.getRequestURI()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleUnexpected(Exception ex, HttpServletRequest request) {
        String traceId = traceId();
        log.error("[{}] Unhandled exception at {}", traceId, request.getRequestURI(), ex);
        return ResponseEntity.status(ErrorCode.INTERNAL_ERROR.status())
                .body(ApiError.of(ErrorCode.INTERNAL_ERROR,
                        "Something went wrong. Quote trace id " + traceId + " if you contact support.",
                        traceId, request.getRequestURI()));
    }

    private String traceId() {
        return UUID.randomUUID().toString().substring(0, 8);
    }
}
