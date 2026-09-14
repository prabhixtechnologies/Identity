package com.prabhix.identity.admin;

import com.prabhix.identity.challenge.PasswordlessService;
import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.config.IdentityProperties;
import com.prabhix.identity.event.AuthEventQueries;
import com.prabhix.identity.event.AuthEventRecord;
import com.prabhix.identity.event.AuthEventRecorder;
import com.prabhix.identity.event.AuthEventRepository;
import com.prabhix.identity.event.AuthEventType;
import com.prabhix.identity.jwks.SigningKeyProvider;
import com.prabhix.identity.security.RequestMetadata;
import com.prabhix.identity.security.ServiceTokenAuthenticator.Actor;
import com.prabhix.identity.session.DeviceSession;
import com.prabhix.identity.session.SessionService;
import com.prabhix.identity.user.AuthIdentity;
import com.prabhix.identity.user.AuthIdentity.AuthProvider;
import com.prabhix.identity.user.AuthIdentityRepository;
import com.prabhix.identity.user.CredentialService;
import com.prabhix.identity.user.IdentityUser;
import com.prabhix.identity.user.IdentityUser.UserStatus;
import com.prabhix.identity.user.IdentityUserRepository;
import com.prabhix.identity.user.UserAdminQueries;
import com.prabhix.identity.web.AdminDtos.AuthEvent;
import com.prabhix.identity.web.AdminDtos.ClientSummary;
import com.prabhix.identity.web.AdminDtos.CredentialSummary;
import com.prabhix.identity.web.AdminDtos.KeySummary;
import com.prabhix.identity.web.AdminDtos.Page;
import com.prabhix.identity.web.AdminDtos.SessionSummary;
import com.prabhix.identity.web.AdminDtos.UserDetail;
import com.prabhix.identity.web.AdminDtos.UserSummary;
import com.prabhix.identity.webauthn.WebAuthnCredential;
import com.prabhix.identity.webauthn.WebAuthnCredentialRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static com.prabhix.identity.event.AuthEventRecorder.details;

/**
 * Staff actions on accounts, clients and keys, always named for a person.
 *
 * <p>{@code actor_user_id} on every write is the staff member in {@code X-Prabhix-Acting-User}, not
 * the calling service. "The admin console disabled this account" is not an answer an investigation
 * can use; a user id is.
 */
@Service
@RequiredArgsConstructor
public class InternalAdminService {

    private static final int DEFAULT_LIMIT = 20;
    private static final int MAX_LIMIT = 100;

    private final UserAdminQueries userQueries;
    private final AuthEventQueries eventQueries;
    private final IdentityUserRepository users;
    private final AuthIdentityRepository identities;
    private final WebAuthnCredentialRepository passkeys;
    private final AuthEventRepository events;
    private final CredentialService credentials;
    private final SessionService sessions;
    private final PasswordlessService passwordless;
    private final SigningKeyProvider signingKeys;
    private final IdentityProperties properties;
    private final JdbcTemplate jdbc;
    private final AuthEventRecorder recorder;

    @Transactional(readOnly = true)
    public Page<UserSummary> searchUsers(String query, String status, String cursor, Integer limit) {
        UserStatus parsed = parseStatus(status);
        int pageSize = pageSize(limit);
        UserAdminQueries.Result result = userQueries.search(query, parsed, cursor, pageSize);
        Map<UUID, Integer> passkeyCounts = passkeyCounts(result.items());
        Set<UUID> googleLinked = googleLinked(result.items());
        List<UserSummary> items = result.items().stream()
                .map(user -> toSummary(user,
                        passkeyCounts.getOrDefault(user.getId(), 0),
                        googleLinked.contains(user.getId())))
                .toList();
        return new Page<>(items, result.nextCursor(), result.total());
    }

    @Transactional(readOnly = true)
    public UserDetail getUser(UUID userId) {
        IdentityUser user = requireKnown(userId);
        List<WebAuthnCredential> userPasskeys = passkeys.findByUserId(userId);
        boolean google = identities.existsByUserIdAndProvider(userId, AuthProvider.GOOGLE);
        UserSummary summary = toSummary(user, userPasskeys.size(), google);

        List<SessionSummary> sessionViews = sessions.listActive(userId).stream()
                .map(this::toSession)
                .toList();

        List<CredentialSummary> credentialViews = new ArrayList<>();
        if (user.hasPassword()) {
            credentialViews.add(new CredentialSummary("password", null, user.getPasswordChangedAt(), null));
        }
        for (WebAuthnCredential passkey : userPasskeys) {
            credentialViews.add(new CredentialSummary(
                    "passkey", passkey.getLabel(), passkey.getCreatedAt(), passkey.getLastUsedAt()));
        }
        for (AuthIdentity identity : identities.findByUserId(userId)) {
            credentialViews.add(new CredentialSummary(
                    identity.getProvider().name().toLowerCase(),
                    identity.getProviderEmail(),
                    identity.getLinkedAt(),
                    identity.getLastLoginAt()));
        }

        List<AuthEvent> recent = events.findTop20ByUserIdOrderByOccurredAtDesc(userId).stream()
                .map(InternalAdminService::toEvent)
                .toList();

        return new UserDetail(
                summary,
                user.getPhone(),
                user.getPhoneVerifiedAt() != null,
                user.getLockedUntil(),
                user.getFailedLoginAttempts(),
                sessionViews,
                credentialViews,
                recent);
    }

    @Transactional
    public void disable(UUID userId, Actor actor) {
        IdentityUser user = requireKnown(userId);
        user.setStatus(UserStatus.DISABLED);
        users.save(user);
        sessions.revokeAll(userId, "admin_disabled");
        recorder.asActor(AuthEventType.ADMIN_USER_DISABLED, actor.userId(), user.getId(), user.getEmail(),
                details("reason", actor.reason()));
    }

    @Transactional
    public void enable(UUID userId, Actor actor) {
        IdentityUser user = requireKnown(userId);
        if (user.getStatus() == UserStatus.DISABLED) {
            user.setStatus(UserStatus.ACTIVE);
            users.save(user);
        }
        recorder.asActor(AuthEventType.ADMIN_USER_ENABLED, actor.userId(), user.getId(), user.getEmail(),
                details("reason", actor.reason()));
    }

    @Transactional
    public void unlock(UUID userId, Actor actor) {
        IdentityUser user = requireKnown(userId);
        credentials.resetLoginFailures(user);
        recorder.asActor(AuthEventType.ADMIN_USER_UNLOCKED, actor.userId(), user.getId(), user.getEmail(),
                details("reason", actor.reason()));
    }

    @Transactional
    public void forceReset(UUID userId, Actor actor) {
        IdentityUser user = requireKnown(userId);
        credentials.clearPassword(user);
        sessions.revokeAll(userId, "admin_force_reset");
        passwordless.sendResetLink(user, RequestMetadata.current()
                .map(RequestMetadata::clientIp)
                .orElse(null));
        recorder.asActor(AuthEventType.ADMIN_FORCE_RESET, actor.userId(), user.getId(), user.getEmail(),
                details("reason", actor.reason()));
    }

    @Transactional
    public void revokeSessions(UUID userId, Actor actor) {
        IdentityUser user = requireKnown(userId);
        sessions.revokeAll(userId, "admin_revoked");
        recorder.asActor(AuthEventType.ADMIN_SESSIONS_REVOKED, actor.userId(), user.getId(), user.getEmail(),
                details("reason", actor.reason()));
    }

    @Transactional(readOnly = true)
    public List<ClientSummary> clients() {
        return jdbc.query("""
                select client_id, client_name, client_authentication_methods,
                       redirect_uris, post_logout_redirect_uris, scopes
                from oauth2_registered_client
                order by client_id
                """, (rs, row) -> new ClientSummary(
                rs.getString("client_id"),
                rs.getString("client_name"),
                isConfidential(rs.getString("client_authentication_methods")),
                splitCsv(rs.getString("redirect_uris")),
                splitCsv(rs.getString("post_logout_redirect_uris")),
                splitCsv(rs.getString("scopes"))));
    }

    @Transactional(readOnly = true)
    public List<KeySummary> keys() {
        String currentId = signingKeys.active().keyId();
        return signingKeys.published().stream()
                .map(jwk -> new KeySummary(
                        jwk.getId(),
                        "RS256",
                        null,
                        null,
                        null,
                        currentId.equals(jwk.getId())))
                .toList();
    }

    @Transactional(readOnly = true)
    public Page<AuthEvent> events(UUID userId, String type, Instant since, String cursor, Integer limit) {
        AuthEventType parsed = parseType(type);
        int pageSize = pageSize(limit);
        AuthEventQueries.Result result = eventQueries.search(userId, parsed, since, cursor, pageSize);
        return new Page<>(
                result.items().stream().map(InternalAdminService::toEvent).toList(),
                result.nextCursor(),
                result.total());
    }

    private IdentityUser requireKnown(UUID userId) {
        return users.findByIdAndDeletedAtIsNull(userId)
                .orElseThrow(() -> ApiException.notFound("That account"));
    }

    private UserSummary toSummary(IdentityUser user, int passkeyCount, boolean googleLinked) {
        return new UserSummary(
                user.getId(),
                user.getEmail(),
                user.getFullName(),
                user.getStatus().name(),
                user.isEmailVerified(),
                user.isLockedNow(),
                user.hasPassword(),
                passkeyCount,
                googleLinked,
                user.getCreatedAt(),
                user.getLastLoginAt());
    }

    private SessionSummary toSession(DeviceSession session) {
        Instant expiresAt = session.getCookieExpiresAt() != null
                ? session.getCookieExpiresAt()
                : session.getCreatedAt() == null
                        ? null
                        : session.getCreatedAt().plus(properties.token().refreshTokenTtl());
        return new SessionSummary(
                session.getId(),
                null,
                session.getIpAddress(),
                session.getUserAgent(),
                session.getCreatedAt(),
                session.getLastSeenAt(),
                expiresAt);
    }

    private static AuthEvent toEvent(AuthEventRecord row) {
        return new AuthEvent(
                row.getId(),
                row.getUserId(),
                row.getEmail(),
                row.getType() == null ? null : row.getType().name(),
                row.getOutcome() == null ? null : row.getOutcome().name(),
                row.getClientId(),
                row.getIpAddress(),
                row.getUserAgent(),
                row.getDetails(),
                row.getOccurredAt());
    }

    private Map<UUID, Integer> passkeyCounts(List<IdentityUser> page) {
        if (page.isEmpty()) {
            return Map.of();
        }
        List<UUID> ids = page.stream().map(IdentityUser::getId).toList();
        Map<UUID, Integer> counts = new HashMap<>();
        for (WebAuthnCredential row : passkeys.findByUserIdIn(ids)) {
            counts.merge(row.getUserId(), 1, Integer::sum);
        }
        return counts;
    }

    private Set<UUID> googleLinked(List<IdentityUser> page) {
        if (page.isEmpty()) {
            return Set.of();
        }
        List<UUID> ids = page.stream().map(IdentityUser::getId).toList();
        return identities.findByUserIdIn(ids).stream()
                .filter(identity -> identity.getProvider() == AuthProvider.GOOGLE)
                .map(AuthIdentity::getUserId)
                .collect(Collectors.toCollection(HashSet::new));
    }

    private static UserStatus parseStatus(String status) {
        if (status == null || status.isBlank()) {
            return null;
        }
        try {
            return UserStatus.valueOf(status.trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            throw ApiException.of(ErrorCode.VALIDATION_FAILED, "That status is not valid");
        }
    }

    private static AuthEventType parseType(String type) {
        if (type == null || type.isBlank()) {
            return null;
        }
        try {
            return AuthEventType.valueOf(type.trim());
        } catch (IllegalArgumentException ex) {
            throw ApiException.of(ErrorCode.VALIDATION_FAILED, "That event type is not valid");
        }
    }

    private static int pageSize(Integer limit) {
        if (limit == null || limit <= 0) {
            return DEFAULT_LIMIT;
        }
        return Math.min(limit, MAX_LIMIT);
    }

    private static boolean isConfidential(String methods) {
        if (methods == null || methods.isBlank()) {
            return true;
        }
        return Arrays.stream(methods.split(","))
                .map(String::trim)
                .anyMatch(method -> !"none".equalsIgnoreCase(method));
    }

    private static List<String> splitCsv(String csv) {
        if (csv == null || csv.isBlank()) {
            return List.of();
        }
        return Arrays.stream(csv.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }
}
