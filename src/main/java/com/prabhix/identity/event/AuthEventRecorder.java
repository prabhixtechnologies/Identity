package com.prabhix.identity.event;

import com.prabhix.identity.event.AuthEventType.Outcome;
import com.prabhix.identity.security.AuthenticatedCaller;
import com.prabhix.identity.security.RequestMetadata;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Writes the audit trail, and never lets writing it break the thing being audited.
 *
 * <p>Two properties, both load-bearing:
 *
 * <ul>
 *   <li><b>It never throws into the caller.</b> A sign-in that fails because the audit insert failed
 *       is a worse outcome than a sign-in with no audit row, so every failure here is logged at
 *       {@code WARN} and swallowed.
 *   <li><b>It survives the caller's rollback.</b> Most of what is worth recording — a wrong password,
 *       a lockout, a refused credential removal — is recorded by a flow that is about to throw, and a
 *       thrown {@code ApiException} rolls the surrounding transaction back. So when a transaction is
 *       active the row is written after it completes, in a transaction of its own; otherwise it is
 *       written immediately. Either way the row lands whether the flow succeeded or not.
 * </ul>
 *
 * <p>The request's address, user agent and OAuth client are captured on the calling thread, before
 * anything is deferred, so the row describes the request that caused it rather than whatever thread
 * happens to write it.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthEventRecorder {

    private final AuthEventWriter writer;

    public void success(AuthEventType type, UUID userId, String email, Map<String, ?> details) {
        record(type, Outcome.SUCCESS, userId, email, null, details);
    }

    public void failure(AuthEventType type, UUID userId, String email, Map<String, ?> details) {
        record(type, Outcome.FAILURE, userId, email, null, details);
    }

    public void denied(AuthEventType type, UUID userId, String email, Map<String, ?> details) {
        record(type, Outcome.DENIED, userId, email, null, details);
    }

    /** For staff actions: {@code actorUserId} is the person behind the calling service. */
    public void asActor(AuthEventType type, UUID actorUserId, UUID userId, String email,
                        Map<String, ?> details) {
        record(type, Outcome.SUCCESS, userId, email, actorUserId, details);
    }

    public void record(AuthEventType type,
                       Outcome outcome,
                       UUID userId,
                       String email,
                       UUID actorUserId,
                       Map<String, ?> details) {
        try {
            AuthEventRecord row = new AuthEventRecord();
            row.setType(type);
            row.setOutcome(outcome);
            row.setUserId(userId);
            row.setEmail(email);
            row.setActorUserId(actorUserId);
            if (details != null) {
                row.setDetails(new LinkedHashMap<>(details));
            }
            RequestMetadata.current().ifPresent(request -> {
                row.setIpAddress(RequestMetadata.clientIp(request));
                row.setUserAgent(RequestMetadata.userAgent(request));
            });
            row.setClientId(callerClientId());
            // Explicit so that a client id recorded by the flow (say, a hosted login that knows
            // which /authorize request it is finishing) is not overwritten by the caller lookup.
            if (details != null && details.get("clientId") instanceof String clientId && row.getClientId() == null) {
                row.setClientId(clientId);
            }
            persist(row);
        } catch (RuntimeException ex) {
            log.warn("Could not record {} {} for user {}: {}", type, outcome, userId, ex.getMessage());
        }
    }

    /**
     * Builds a details map, skipping null values.
     *
     * <p>{@code Map.of} refuses nulls, and almost every call site has an optional field or two — an
     * address that may be unknown, a reason nobody gave.
     */
    public static Map<String, Object> details(Object... keyValues) {
        if (keyValues.length % 2 != 0) {
            throw new IllegalArgumentException("details() takes key/value pairs");
        }
        Map<String, Object> map = new LinkedHashMap<>();
        for (int i = 0; i < keyValues.length; i += 2) {
            if (keyValues[i + 1] != null) {
                map.put(String.valueOf(keyValues[i]), keyValues[i + 1]);
            }
        }
        return map;
    }

    private void persist(AuthEventRecord row) {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCompletion(int status) {
                    writeQuietly(row);
                }
            });
        } else {
            writeQuietly(row);
        }
    }

    private void writeQuietly(AuthEventRecord row) {
        try {
            writer.write(row);
        } catch (RuntimeException ex) {
            log.warn("Could not record {} {} for user {}: {}",
                    row.getType(), row.getOutcome(), row.getUserId(), ex.getMessage());
        }
    }

    private static String callerClientId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null && authentication.getPrincipal() instanceof AuthenticatedCaller caller
                ? caller.clientId()
                : null;
    }
}
