package com.prabhix.identity.security;

import java.util.UUID;

/**
 * Who is calling one of this service's own protected endpoints.
 *
 * <p>Two fields, and no more on purpose. The platform's equivalent carries an organization and a
 * permission set, which is what made its principal impossible to build without asking the org module
 * first. Nothing here needs either: the endpoints a caller can reach are all about their own account.
 */
public record AuthenticatedCaller(UUID userId, UUID sessionId) {
}
