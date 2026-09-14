package com.prabhix.identity.security;

import java.security.Principal;
import java.util.UUID;

/**
 * Who is calling one of this service's own protected endpoints.
 *
 * <p>Three fields, and no more on purpose. The platform's equivalent carries an organization and a
 * permission set, which is what made its principal impossible to build without asking the org module
 * first. Nothing here needs either: the endpoints a caller can reach are all about their own account.
 *
 * <p>A {@link Principal} so that {@code Authentication.getName()} is the user id, the same thing the
 * hosted login session's authentication answers — which keeps log lines and the logout handler
 * indifferent to which of the two produced the principal.
 *
 * @param sessionId the {@code sid} of the bearer token — a device session for a token minted by
 *     {@code /api/v1/auth/*}, an authorization id for one minted by {@code /oauth2/token}. Null when
 *     the caller is the hosted browser session on {@code /account}, which has neither.
 * @param clientId the OAuth client the token was issued to, from its {@code aud}. Null for tokens
 *     from the direct sign-in endpoints and for the hosted session; recorded on audit events.
 */
public record AuthenticatedCaller(UUID userId, UUID sessionId, String clientId) implements Principal {

    public AuthenticatedCaller(UUID userId, UUID sessionId) {
        this(userId, sessionId, null);
    }

    /** True for the hosted {@code /account} page, which authenticates with the login session. */
    public boolean isHostedSession() {
        return sessionId == null;
    }

    @Override
    public String getName() {
        return userId.toString();
    }
}
