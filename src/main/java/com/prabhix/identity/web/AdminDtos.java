package com.prabhix.identity.web;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * JSON shapes of {@code /internal/admin/*}, matching {@code IdentityAdmin} field-for-field.
 *
 * <p>Duplicated rather than imported from the client jar: the server must not depend on a library
 * published for products, and a field that drifts here is a broken admin console, not a compile
 * error in a module nobody runs in this build.
 */
public final class AdminDtos {

    private AdminDtos() {
    }

    public record Page<T>(List<T> items, String nextCursor, long total) {
    }

    public record UserAction(String reason) {
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
}
