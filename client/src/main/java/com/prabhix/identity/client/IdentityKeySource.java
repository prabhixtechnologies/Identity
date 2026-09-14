package com.prabhix.identity.client;

import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.Jwks;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.client.RestClient;

import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;

/**
 * The public keys that verify tokens issued by Prabhix Identity.
 *
 * <p>Fetched from identity's published JWKS and cached by key id. Only public keys ever cross this
 * boundary, which is the whole reason identity signs RS256 rather than HS256: under a shared HMAC
 * secret every service that can verify a token can also mint one, so any single compromised product
 * could issue itself a platform-admin token. Here a product can check a signature and cannot produce
 * one.
 */
public class IdentityKeySource {

    private static final Logger log = LoggerFactory.getLogger(IdentityKeySource.class);

    private final IdentityClientProperties config;
    private final RestClient http;

    /** Guards a refresh so a burst of requests after a rotation produces one fetch, not hundreds. */
    private final ReentrantLock refreshLock = new ReentrantLock();

    private volatile Map<String, PublicKey> keys = Map.of();
    private volatile Instant fetchedAt = Instant.EPOCH;
    private volatile Instant lastAttemptAt = Instant.EPOCH;

    public IdentityKeySource(IdentityClientProperties config, RestClient http) {
        this.config = config;
        this.http = http;
    }

    /**
     * The key a token names, or empty if identity does not publish it.
     *
     * <p>A key id absent from the cache triggers one refresh, because that is exactly what a rotation
     * looks like from here: tokens start arriving signed by a key this instance has never seen. The
     * refresh is rate-limited so the same signal cannot be produced deliberately — a token naming a
     * random key id costs an attacker nothing and would otherwise cost us a round trip each time.
     *
     * @param keyId the {@code kid} header. Never used as anything but a map lookup: the token names
     *     which published key to check it against, and cannot supply one.
     */
    public Optional<PublicKey> verificationKey(String keyId) {
        if (!config.enabled() || keyId == null || keyId.isBlank()) {
            return Optional.empty();
        }

        Map<String, PublicKey> current = keys;
        PublicKey known = current.get(keyId);
        if (known != null && !isStale()) {
            return Optional.of(known);
        }
        if (known != null) {
            // Stale but present. Serve it and refresh, rather than making this request wait on a
            // network call for a key that has not actually changed.
            refreshIfAllowed();
            return Optional.of(known);
        }

        refreshIfAllowed();
        return Optional.ofNullable(keys.get(keyId));
    }

    /** The key ids currently cached — for health pages, never for verification. */
    public java.util.Set<String> cachedKeyIds() {
        return keys.keySet();
    }

    private boolean isStale() {
        return fetchedAt.plus(config.jwksCacheTtl()).isBefore(Instant.now());
    }

    private void refreshIfAllowed() {
        Instant now = Instant.now();
        Duration sinceAttempt = Duration.between(lastAttemptAt, now);
        if (sinceAttempt.compareTo(config.jwksMinRefreshInterval()) < 0) {
            return;
        }
        // Non-blocking: whoever holds the lock is already fetching, and this request would rather
        // fail to find the key than hold a servlet thread waiting for someone else's HTTP call.
        if (!refreshLock.tryLock()) {
            return;
        }
        try {
            lastAttemptAt = Instant.now();
            fetch();
        } finally {
            refreshLock.unlock();
        }
    }

    private void fetch() {
        String uri = config.effectiveJwksUri();
        try {
            String body = http.get().uri(uri).retrieve().body(String.class);
            if (body == null || body.isBlank()) {
                log.warn("Identity JWKS at {} returned an empty body; keeping {} cached", uri, keys.size());
                return;
            }

            Map<String, PublicKey> parsed = new HashMap<>();
            for (Jwk<?> jwk : Jwks.setParser().build().parse(body).getKeys()) {
                // A private key here would mean identity is publishing something it must not, and a
                // key with no id cannot be selected by a token's kid, so neither is usable.
                if (jwk.toKey() instanceof PublicKey publicKey && jwk.getId() != null) {
                    parsed.put(jwk.getId(), publicKey);
                }
            }

            if (parsed.isEmpty()) {
                log.warn("Identity JWKS at {} had no usable public keys; keeping {} cached", uri, keys.size());
                return;
            }

            keys = Collections.unmodifiableMap(parsed);
            fetchedAt = Instant.now();
            log.info("Loaded {} identity verification key(s) from {}", parsed.size(), uri);
        } catch (RuntimeException ex) {
            // Deliberately keeps the previous key set. Identity being briefly unreachable should not
            // invalidate every session on this instance; the old keys are still the right ones.
            log.warn("Could not refresh identity JWKS from {}: {}", uri, ex.getMessage());
        }
    }
}
