package com.prabhix.identity.security;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.common.Secrets;
import com.prabhix.identity.config.IdentityProperties;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.UUID;

/**
 * The lock on {@code /internal}: a shared token that only our own services hold.
 *
 * <p>Checked inside the controllers rather than by a filter chain, because {@code /internal/**} is
 * {@code permitAll} at the Spring Security layer — the caller is a product, not a person, and there
 * is no bearer token to verify. Caddy not routing {@code /internal} at all is the first lock; this is
 * the second.
 *
 * <p>The admin surface adds a second requirement on top: the staff member on whose behalf the
 * product is calling, so that "who disabled this account" has an answer that is a person and not
 * "the admin console".
 */
@Component
@RequiredArgsConstructor
public class ServiceTokenAuthenticator {

    public static final String SERVICE_TOKEN_HEADER = "X-Prabhix-Service-Token";
    public static final String ACTING_USER_HEADER = "X-Prabhix-Acting-User";
    public static final String ACTING_REASON_HEADER = "X-Prabhix-Acting-Reason";

    private final IdentityProperties properties;

    /**
     * A blank configured token disables the endpoint rather than accepting a blank header, so a
     * deployment that forgot to set one fails closed.
     */
    public void requireServiceToken(HttpServletRequest request) {
        String expected = properties.serviceToken();
        if (expected == null || expected.isBlank()) {
            throw ApiException.of(ErrorCode.FEATURE_DISABLED,
                    "This deployment has no service token configured");
        }
        String presented = request.getHeader(SERVICE_TOKEN_HEADER);
        if (presented == null || !Secrets.constantTimeEquals(expected, presented)) {
            throw ApiException.of(ErrorCode.UNAUTHENTICATED, "That service token is not valid");
        }
    }

    /**
     * The service token plus a named staff member.
     *
     * @throws ApiException {@code ACTING_USER_REQUIRED} (400) when the header is absent or is not a
     *     UUID. A 400 and not a 401: the service authenticated fine, its request is incomplete.
     */
    public Actor requireActor(HttpServletRequest request) {
        requireServiceToken(request);
        UUID actingUser = actingUser(request).orElseThrow(() -> ApiException.of(
                ErrorCode.ACTING_USER_REQUIRED,
                ACTING_USER_HEADER + " must carry the id of the staff member making this request"));
        return new Actor(actingUser, blankToNull(request.getHeader(ACTING_REASON_HEADER)));
    }

    /** The acting user when one was named, for routes where it is optional. */
    public Optional<UUID> actingUser(HttpServletRequest request) {
        String header = request.getHeader(ACTING_USER_HEADER);
        if (header == null || header.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.of(UUID.fromString(header.trim()));
        } catch (IllegalArgumentException ex) {
            return Optional.empty();
        }
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    /** @param reason free text from {@code X-Prabhix-Acting-Reason}; null when none was given */
    public record Actor(UUID userId, String reason) {
    }
}
