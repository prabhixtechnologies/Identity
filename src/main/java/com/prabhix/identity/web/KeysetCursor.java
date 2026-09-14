package com.prabhix.identity.web;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

/**
 * Opaque keyset cursor of {@code (time, id)}, newest-first.
 *
 * <p>Offset pagination would skip or repeat rows as the table moves under the reader — a new event
 * during a walk of {@code /internal/admin/events} would shift everything by one. A keyset does not.
 */
public final class KeysetCursor {

    private KeysetCursor() {
    }

    public static String encode(Instant time, UUID id) {
        String raw = time.toEpochMilli() + ":" + id;
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(raw.getBytes(StandardCharsets.UTF_8));
    }

    public static Position decode(String cursor) {
        try {
            String raw = new String(Base64.getUrlDecoder().decode(cursor), StandardCharsets.UTF_8);
            int split = raw.indexOf(':');
            if (split <= 0 || split == raw.length() - 1) {
                throw invalid();
            }
            Instant time = Instant.ofEpochMilli(Long.parseLong(raw.substring(0, split)));
            UUID id = UUID.fromString(raw.substring(split + 1));
            return new Position(time, id);
        } catch (RuntimeException ex) {
            throw invalid();
        }
    }

    private static ApiException invalid() {
        return ApiException.of(ErrorCode.VALIDATION_FAILED, "That cursor is not valid");
    }

    public record Position(Instant time, UUID id) {
    }
}
