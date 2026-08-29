package com.prabhix.identity.integration;

import com.prabhix.identity.challenge.AuthChallenge;
import com.prabhix.identity.challenge.AuthChallenge.ChallengePurpose;
import com.prabhix.identity.challenge.AuthChallengeRepository;
import com.prabhix.identity.common.Secrets;
import com.prabhix.identity.session.DeviceSession;
import com.prabhix.identity.session.DeviceSessionRepository;
import com.prabhix.identity.session.RefreshToken;
import com.prabhix.identity.session.RefreshTokenRepository;
import com.prabhix.identity.user.AuthIdentity;
import com.prabhix.identity.user.AuthIdentity.AuthProvider;
import com.prabhix.identity.user.AuthIdentityRepository;
import com.prabhix.identity.user.IdentityUser;
import com.prabhix.identity.user.IdentityUserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Proves the Flyway migration and the JPA entities agree, against real Postgres.
 *
 * <p>{@code ddl-auto: validate} means the context will not even start if a column is named
 * differently in one place than the other, so most of the value here is in the fact that this test
 * boots at all. The assertions cover what validation cannot see: {@code citext} making email lookup
 * case-insensitive, {@code jsonb} round-tripping a map, and the partial unique indexes that stop two
 * live sessions sharing a device.
 *
 * <p>H2 would run faster and prove none of it: it has neither type, so a migration that cannot apply
 * in production would pass here.
 *
 * <p>Deliberately not {@code @Transactional}. Half of these tests provoke a constraint violation and
 * then keep working — Postgres aborts a transaction on the first such error, so a single wrapping
 * transaction would turn the rest of each method into a cascade of unrelated failures. The cost is
 * that rows persist across methods, so every test uses addresses and device ids of its own.
 */
@Tag("integration")
@Testcontainers
@SpringBootTest
class IdentitySchemaIntegrationTest {

    @Container
    @SuppressWarnings("resource")
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("prabhix_identity_test");

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        // A local profile, so SigningKeyProvider is allowed to generate an ephemeral key rather than
        // demanding IDENTITY_SIGNING_KEY.
        registry.add("spring.profiles.active", () -> "dev");
    }

    @Autowired
    private IdentityUserRepository users;

    @Autowired
    private AuthIdentityRepository identities;

    @Autowired
    private DeviceSessionRepository sessions;

    @Autowired
    private RefreshTokenRepository refreshTokens;

    @Autowired
    private AuthChallengeRepository challenges;

    @Autowired
    private JdbcTemplate jdbc;

    private IdentityUser persistedUser(String email) {
        IdentityUser user = new IdentityUser();
        user.setEmail(email);
        user.setFullName("Demo Owner");
        return users.save(user);
    }

    @Test
    @DisplayName("an address is stored lowercase and trimmed however it arrives")
    void emailIsNormalizedOnWrite() {
        UUID id = persistedUser("  Normalized@PrabhixTechnologies.COM ").getId();

        // Read straight out of Postgres, so a getter cannot be what is doing the folding.
        assertThat(jdbc.queryForObject("select email from users where id = ?", String.class, id))
                .isEqualTo("normalized@prabhixtechnologies.com");
    }

    @Test
    @DisplayName("address lookup ignores case and surrounding space")
    void emailLookupIgnoresCase() {
        persistedUser("lookup@prabhixtechnologies.com");

        assertThat(users.findActiveByEmail("Lookup@PrabhixTechnologies.COM")).isPresent();
        assertThat(users.activeEmailExists(" LOOKUP@PRABHIXTECHNOLOGIES.COM ")).isTrue();
        assertThat(users.findActiveByEmails(List.of("LOOKUP@prabhixtechnologies.com"))).hasSize(1);
    }

    @Test
    @DisplayName("citext still guards the table against case-only duplicates from outside the app")
    void citextGuardsAgainstDirectInserts() {
        persistedUser("direct@prabhixtechnologies.com");

        // Straight SQL, the way the import script and a psql session reach this table. Normalizing in
        // Java protects the application's own writes; citext is what protects it from everything else.
        assertThatThrownBy(() -> jdbc.update(
                "insert into users (id, email, full_name, timezone, locale, status, platform_admin, "
                        + "failed_login_attempts, created_at, updated_at, version) values "
                        + "(gen_random_uuid(), 'Direct@PrabhixTechnologies.com', 'Imported', "
                        + "'Asia/Kolkata', 'en-IN', 'ACTIVE', false, 0, now(), now(), 0)"))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    @DisplayName("two accounts cannot share an address, whatever the case")
    void emailIsUnique() {
        persistedUser("clash@prabhixtechnologies.com");

        IdentityUser duplicate = new IdentityUser();
        duplicate.setEmail("Clash@PrabhixTechnologies.com");
        duplicate.setFullName("Somebody Else");

        assertThatThrownBy(() -> users.saveAndFlush(duplicate))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    @DisplayName("the same provider account cannot be linked twice")
    void providerSubjectIsUnique() {
        IdentityUser user = persistedUser("google@prabhixtechnologies.com");
        identities.save(link(user.getId(), "google-subject-1"));

        // Without this a race on first sign-in links one Google account to two users, and the next
        // sign-in picks whichever row it happens to find.
        assertThatThrownBy(() -> identities.saveAndFlush(link(user.getId(), "google-subject-1")))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    private AuthIdentity link(UUID userId, String subject) {
        AuthIdentity identity = new AuthIdentity();
        identity.setUserId(userId);
        identity.setProvider(AuthProvider.GOOGLE);
        identity.setProviderSubject(subject);
        identity.setProviderEmail("google@prabhixtechnologies.com");
        identity.setRawProfile(Map.of("hd", "prabhixtechnologies.com", "picture", "https://x/y.png"));
        return identity;
    }

    @Test
    @DisplayName("a jsonb profile survives a round trip")
    void jsonbRoundTrips() {
        IdentityUser user = persistedUser("profile@prabhixtechnologies.com");
        UUID id = identities.save(link(user.getId(), "google-subject-2")).getId();
        identities.flush();

        AuthIdentity reloaded = identities.findById(id).orElseThrow();

        assertThat(reloaded.getRawProfile())
                .containsEntry("hd", "prabhixtechnologies.com")
                .containsEntry("picture", "https://x/y.png");
    }

    @Test
    @DisplayName("one device holds one live session, but revoked ones are kept")
    void oneLiveSessionPerDevice() {
        IdentityUser user = persistedUser("device@prabhixtechnologies.com");
        DeviceSession first = sessions.saveAndFlush(session(user.getId(), "phone-1"));

        assertThatThrownBy(() -> sessions.saveAndFlush(session(user.getId(), "phone-1")))
                .isInstanceOf(DataIntegrityViolationException.class);

        // The index is partial, so revoking the first frees the device id again. The revoked row
        // stays, because the audit trail of who signed out when is part of what this table is for.
        first.revoke("logout");
        sessions.saveAndFlush(first);
        assertThat(sessions.saveAndFlush(session(user.getId(), "phone-1")).getId()).isNotNull();
        assertThat(sessions.findById(first.getId())).isPresent();
    }

    private DeviceSession session(UUID userId, String deviceId) {
        DeviceSession session = new DeviceSession();
        session.setUserId(userId);
        session.setDeviceId(deviceId);
        session.setDeviceName("Phone");
        return session;
    }

    @Test
    @DisplayName("two sessions cannot share a cookie hash, and null hashes do not collide")
    void cookieHashIsUniqueWhenPresent() {
        IdentityUser user = persistedUser("cookie@prabhixtechnologies.com");
        DeviceSession first = sessions.saveAndFlush(session(user.getId(), "laptop-1"));
        DeviceSession second = sessions.saveAndFlush(session(user.getId(), "laptop-2"));
        String hash = Secrets.sha256("a-cookie-value");

        first.setCookieTokenHash(hash);
        first.setCookieExpiresAt(Instant.now().plus(30, ChronoUnit.DAYS));
        sessions.saveAndFlush(first);
        second.setCookieTokenHash(hash);

        assertThatThrownBy(() -> sessions.saveAndFlush(second))
                .isInstanceOf(DataIntegrityViolationException.class);
        // Every phone and every pre-cookie web session has a null hash, so the index has to be
        // partial or the second such session would collide with the first.
        assertThat(sessions.saveAndFlush(session(user.getId(), "laptop-3")).getId()).isNotNull();
    }

    @Test
    @DisplayName("a refresh token points at a session and can name its successor")
    void refreshTokenChain() {
        IdentityUser user = persistedUser("refresh@prabhixtechnologies.com");
        DeviceSession session = sessions.saveAndFlush(session(user.getId(), "web-1"));

        RefreshToken first = refreshTokens.saveAndFlush(token(user.getId(), session.getId(), "raw-1"));
        RefreshToken second = refreshTokens.saveAndFlush(token(user.getId(), session.getId(), "raw-2"));
        first.setReplacedBy(second.getId());
        refreshTokens.saveAndFlush(first);

        assertThat(refreshTokens.findByTokenHash(Secrets.sha256("raw-1")))
                .get()
                .satisfies(found -> assertThat(found.getReplacedBy()).isEqualTo(second.getId()));
    }

    private RefreshToken token(UUID userId, UUID sessionId, String raw) {
        RefreshToken token = new RefreshToken();
        token.setUserId(userId);
        token.setSessionId(sessionId);
        token.setTokenHash(Secrets.sha256(raw));
        token.setExpiresAt(Instant.now().plus(30, ChronoUnit.DAYS));
        return token;
    }

    @Test
    @DisplayName("a challenge can exist for an address with no account")
    void challengeUserIdIsNullable() {
        AuthChallenge challenge = new AuthChallenge();
        challenge.setPurpose(ChallengePurpose.MAGIC_LINK);
        challenge.setDestination("Nobody@PrabhixTechnologies.com");
        challenge.setSecretHash(Secrets.sha256("secret"));
        challenge.setExpiresAt(Instant.now().plus(10, ChronoUnit.MINUTES));
        challenge.setMaxAttempts(5);

        AuthChallenge saved = challenges.saveAndFlush(challenge);

        // Nullable on purpose: keeping the row shape identical whether or not the address has an
        // account is part of what stops the endpoint being a membership oracle.
        assertThat(saved.getUserId()).isNull();
        // Requested as mixed case, verified as lowercase — the OTP flow across two requests.
        assertThat(challenges.findNewestUnconsumed(
                "nobody@prabhixtechnologies.com", ChallengePurpose.MAGIC_LINK)).isPresent();
    }

    @Test
    @DisplayName("the users table has no organization column")
    void noProductStateLeakedIn() {
        // The one thing this schema must not grow. A column only the platform can populate is
        // product state in the identity store, and the reason the split exists.
        assertThat(IdentityUser.class.getDeclaredFields())
                .noneSatisfy(field -> assertThat(field.getName().toLowerCase())
                        .containsAnyOf("organization", "shop", "workspace", "permission", "role"));
    }
}
