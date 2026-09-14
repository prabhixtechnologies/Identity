package com.prabhix.identity.client;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * The shapes of identity's internal admin API ({@code /internal/admin/*}).
 *
 * <p>Reached only by a product backend acting for a platform staff member — the oneOps admin BFF in
 * practice. Every call carries the acting user, so identity's own audit trail names a person and not
 * "the platform".
 */
public final class IdentityAdmin {

    private IdentityAdmin() {
    }

    /** Who is asking, for identity's audit trail. */
    public record Actor(UUID userId, String reason) {
        public static Actor of(UUID userId) {
            return new Actor(userId, null);
        }
    }

    public record UserSearch(String query, String status, String cursor, Integer limit) {
        public static UserSearch of(String query) {
            return new UserSearch(query, null, null, null);
        }
    }

    public record EventQuery(UUID userId, String type, Instant since, String cursor, Integer limit) {
    }

    public record Page<T>(List<T> items, String nextCursor, long total) {
    }

    public record UserSummary(UUID id,
                              String email,
                              String fullName,
                              String status,
                              boolean emailVerified,
                              boolean locked,
                              boolean hasPassword,
                              int passkeyCount,
                              boolean googleLinked,
                              Instant createdAt,
                              Instant lastLoginAt) {
    }

    public record SessionSummary(UUID id,
                                 String clientId,
                                 String ipAddress,
                                 String userAgent,
                                 Instant createdAt,
                                 Instant lastSeenAt,
                                 Instant expiresAt) {
    }

    public record CredentialSummary(String type, String label, Instant createdAt, Instant lastUsedAt) {
    }

    public record UserDetail(UserSummary user,
                             String phone,
                             boolean phoneVerified,
                             Instant lockedUntil,
                             int failedLogins,
                             List<SessionSummary> sessions,
                             List<CredentialSummary> credentials,
                             List<AuthEvent> recentEvents) {
    }

    public record ClientSummary(String clientId,
                                String name,
                                boolean confidential,
                                List<String> redirectUris,
                                List<String> postLogoutRedirectUris,
                                List<String> scopes) {
    }

    public record KeySummary(String keyId,
                             String algorithm,
                             Instant createdAt,
                             Instant activeFrom,
                             Instant retiredAt,
                             boolean current) {
    }

    public record AuthEvent(UUID id,
                            UUID userId,
                            String email,
                            String type,
                            String outcome,
                            String clientId,
                            String ipAddress,
                            String userAgent,
                            Map<String, Object> details,
                            Instant occurredAt) {
    }

    /** A staff action on a user; {@code reason} is stored beside the event. */
    public record UserAction(String reason) {
    }
}
