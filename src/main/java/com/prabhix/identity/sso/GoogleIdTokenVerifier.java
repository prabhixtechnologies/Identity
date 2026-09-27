package com.prabhix.identity.sso;

import tools.jackson.databind.JsonNode;
import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.common.Secrets;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Locator;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.Jwks;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Validates Google GIS {@code id_token} values locally when possible, with tokeninfo fallback and a
 * replay cache either way.
 */
@Slf4j
@Component
public class GoogleIdTokenVerifier {

    private static final String TOKENINFO = "https://oauth2.googleapis.com/tokeninfo";
    private static final String JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";
    private static final String REPLAY_PREFIX = "pbx:identity:google:idtoken:";
    private static final Set<String> ISSUERS = Set.of(
            "https://accounts.google.com",
            "accounts.google.com");

    private final RestClient restClient = RestClient.create();
    private final StringRedisTemplate redis;
    private final ConcurrentHashMap<String, Key> keysByKid = new ConcurrentHashMap<>();
    private volatile Instant keysFetchedAt = Instant.EPOCH;

    public GoogleIdTokenVerifier(StringRedisTemplate redis) {
        this.redis = redis;
    }

    public Verified verify(String idToken, String expectedAudience) {
        try {
            return verifyLocally(idToken, expectedAudience);
        } catch (RuntimeException localFailure) {
            log.debug("Local Google id_token verification failed, trying tokeninfo: {}",
                    localFailure.getMessage());
            return verifyWithTokenInfo(idToken, expectedAudience);
        }
    }

    private Verified verifyLocally(String idToken, String expectedAudience) {
        refreshKeysIfStale();
        Locator<Key> locator = header -> {
            Object kid = header.get("kid");
            if (kid == null) {
                throw new IllegalArgumentException("Missing kid");
            }
            Key key = keysByKid.get(kid.toString());
            if (key == null) {
                refreshKeys(true);
                key = keysByKid.get(kid.toString());
            }
            if (key == null) {
                throw new IllegalArgumentException("Unknown Google signing key");
            }
            return key;
        };

        Jws<Claims> parsed = Jwts.parser()
                .keyLocator(locator)
                .requireAudience(expectedAudience)
                .build()
                .parseSignedClaims(idToken);

        Claims claims = parsed.getPayload();
        String issuer = claims.getIssuer();
        if (issuer == null || !ISSUERS.contains(issuer)) {
            throw new IllegalArgumentException("Unexpected issuer");
        }
        if (!Boolean.TRUE.equals(claims.get("email_verified", Boolean.class))
                && !"true".equalsIgnoreCase(String.valueOf(claims.get("email_verified")))) {
            throw ApiException.of(ErrorCode.INVALID_CREDENTIALS, "That Google token is not valid");
        }
        consumeOnce(idToken, claims.getExpiration().toInstant());
        return toVerified(claims);
    }

    private Verified verifyWithTokenInfo(String idToken, String expectedAudience) {
        JsonNode tokenInfo = fetchTokenInfo(idToken);
        if (!expectedAudience.equals(text(tokenInfo, "aud"))) {
            throw invalidToken();
        }
        if (!"true".equalsIgnoreCase(text(tokenInfo, "email_verified"))) {
            throw invalidToken();
        }
        String issuer = text(tokenInfo, "iss");
        if (issuer == null || !ISSUERS.contains(issuer)) {
            throw invalidToken();
        }
        long expSeconds = tokenInfo.path("exp").asLong(0);
        Instant expiresAt = expSeconds > 0 ? Instant.ofEpochSecond(expSeconds) : Instant.now().plusSeconds(300);
        consumeOnce(idToken, expiresAt);
        return new Verified(
                text(tokenInfo, "sub"),
                text(tokenInfo, "email"),
                text(tokenInfo, "name"),
                tokenInfo);
    }

    /** Visible for tests that exercise replay protection without calling Google. */
    void ensureNotReplayed(String idToken, Instant expiresAt) {
        consumeOnce(idToken, expiresAt);
    }

    private void consumeOnce(String idToken, Instant expiresAt) {
        String key = REPLAY_PREFIX + Secrets.sha256(idToken);
        Duration ttl = Duration.between(Instant.now(), expiresAt);
        if (ttl.isNegative() || ttl.isZero()) {
            throw invalidToken();
        }
        if (ttl.compareTo(Duration.ofHours(2)) > 0) {
            ttl = Duration.ofHours(2);
        }
        try {
            Boolean first = redis.opsForValue().setIfAbsent(key, "1", ttl);
            if (Boolean.FALSE.equals(first)) {
                throw invalidToken();
            }
        } catch (ApiException ex) {
            throw ex;
        } catch (RuntimeException ex) {
            log.warn("Google id_token replay cache unavailable; rejecting token: {}", ex.getMessage());
            throw ApiException.of(ErrorCode.DEPENDENCY_UNAVAILABLE,
                    "Google sign-in is temporarily unavailable. Try again.");
        }
    }

    private Verified toVerified(Claims claims) {
        return new Verified(
                claims.getSubject(),
                claims.get("email", String.class),
                claims.get("name", String.class),
                null);
    }

    private void refreshKeysIfStale() {
        if (keysFetchedAt.isBefore(Instant.now().minus(Duration.ofHours(6)))) {
            refreshKeys(false);
        }
    }

    private synchronized void refreshKeys(boolean force) {
        if (!force && keysFetchedAt.isAfter(Instant.now().minus(Duration.ofHours(6)))) {
            return;
        }
        JsonNode document = restClient.get().uri(JWKS_URL).retrieve().body(JsonNode.class);
        if (document == null || !document.has("keys")) {
            throw new IllegalStateException("Google JWKS response was empty");
        }
        ConcurrentHashMap<String, Key> next = new ConcurrentHashMap<>();
        for (JsonNode keyNode : document.get("keys")) {
            Jwk<?> jwk = Jwks.parser().build().parse(keyNode.toString());
            next.put(jwk.getId(), jwk.toKey());
        }
        keysByKid.clear();
        keysByKid.putAll(next);
        keysFetchedAt = Instant.now();
    }

    private JsonNode fetchTokenInfo(String idToken) {
        try {
            JsonNode body = restClient.post()
                    .uri(TOKENINFO)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("id_token=" + URLEncoder.encode(idToken, StandardCharsets.UTF_8))
                    .retrieve()
                    .body(JsonNode.class);
            if (body == null) {
                throw invalidToken();
            }
            return body;
        } catch (RestClientException ex) {
            log.debug("Google tokeninfo rejected an id_token: {}", ex.getMessage());
            throw invalidToken();
        }
    }

    private ApiException invalidToken() {
        return ApiException.of(ErrorCode.INVALID_CREDENTIALS, "That Google token is not valid");
    }

    private String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value != null && !value.isNull() ? value.asText() : null;
    }

    public record Verified(String subject, String email, String name, JsonNode tokenInfoProfile) {
    }
}
