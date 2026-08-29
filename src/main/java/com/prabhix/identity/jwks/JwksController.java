package com.prabhix.identity.jwks;

import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Publishes the public keys that verify tokens this service issues.
 *
 * <p>Public and unauthenticated by design — a public key is not a secret, and every product needs to
 * read this before it can accept a single request.
 */
@RestController
@RequiredArgsConstructor
public class JwksController {

    private final SigningKeyProvider keys;

    @GetMapping("/.well-known/jwks.json")
    public ResponseEntity<Map<String, Object>> jwks() {
        // Each Jwk is already a Map of its JWK members, but copied into a plain LinkedHashMap so the
        // response body does not depend on how Jackson chooses to serialise a jjwt type.
        List<Map<String, Object>> keyList = keys.published().stream()
                .map(jwk -> (Map<String, Object>) new LinkedHashMap<String, Object>(jwk))
                .toList();

        // Cacheable, because every product fetches this on the first request it verifies and the
        // keys change only on rotation. Ten minutes is short enough that a rotation propagates
        // without anyone being asked to restart, and long enough that this is not on the hot path.
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(10, TimeUnit.MINUTES).cachePublic())
                .body(Map.of("keys", keyList));
    }
}
