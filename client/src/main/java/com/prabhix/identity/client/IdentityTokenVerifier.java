package com.prabhix.identity.client;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.LocatorAdapter;
import io.jsonwebtoken.security.SignatureException;

import java.security.Key;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Verifies a token issued by Prabhix Identity and reads the identity claims out of it.
 *
 * <p>Only RS256 is accepted, and the key is chosen by the {@code kid} the token names from the
 * published JWKS. There is no HMAC path: a product that could verify with a shared secret could also
 * mint with it, which is precisely the property the split into an identity service removed. Anything
 * else in {@code alg}, including {@code none}, never reaches a key.
 */
public class IdentityTokenVerifier {

    static final String CLAIM_EMAIL = "email";
    static final String CLAIM_EMAIL_VERIFIED = "email_verified";
    static final String CLAIM_NAME = "name";
    static final String CLAIM_SESSION = "sid";
    static final String CLAIM_AMR = "amr";

    private final IdentityClientProperties config;
    private final IdentityKeySource keys;

    public IdentityTokenVerifier(IdentityClientProperties config, IdentityKeySource keys) {
        this.config = config;
        this.keys = keys;
    }

    /**
     * @throws IdentityTokenException never returns null
     */
    public IdentityToken verify(String token) {
        if (!config.enabled()) {
            throw new IdentityTokenException(IdentityTokenException.Reason.UNTRUSTED,
                    "This deployment does not trust an identity issuer");
        }
        if (token == null || token.isBlank()) {
            throw new IdentityTokenException(IdentityTokenException.Reason.INVALID, "That token is not valid");
        }

        Jws<Claims> jws;
        try {
            jws = Jwts.parser()
                    .clockSkewSeconds(config.clockSkew().toSeconds())
                    .keyLocator(new LocatorAdapter<Key>() {
                        @Override
                        protected Key locate(JwsHeader header) {
                            if (!Jwts.SIG.RS256.getId().equals(header.getAlgorithm())) {
                                throw new SignatureException(
                                        "Unsupported token algorithm " + header.getAlgorithm());
                            }
                            return keys.verificationKey(header.getKeyId())
                                    .orElseThrow(() -> new SignatureException(
                                            "No published identity key with id " + header.getKeyId()));
                        }
                    })
                    .build()
                    .parseSignedClaims(token);
        } catch (ExpiredJwtException ex) {
            throw new IdentityTokenException(IdentityTokenException.Reason.EXPIRED,
                    "Your session has expired", ex);
        } catch (JwtException | IllegalArgumentException ex) {
            throw new IdentityTokenException(IdentityTokenException.Reason.INVALID,
                    "That token is not valid", ex);
        }

        Claims claims = jws.getPayload();
        // Checked after parsing rather than with requireIssuer, so the failure is reported the same
        // way as a bad signature: a token from another issuer is not a special case worth revealing.
        if (!config.issuer().equals(claims.getIssuer())) {
            throw new IdentityTokenException(IdentityTokenException.Reason.INVALID, "That token is not valid");
        }

        return new IdentityToken(
                requiredUuid(claims.getSubject()),
                claims.get(CLAIM_EMAIL, String.class),
                claims.get(CLAIM_NAME, String.class),
                Boolean.TRUE.equals(claims.get(CLAIM_EMAIL_VERIFIED, Boolean.class)),
                optionalUuid(claims.get(CLAIM_SESSION, String.class)),
                claims.getId(),
                toInstant(claims.getIssuedAt()),
                toInstant(claims.getExpiration()),
                readAmr(claims),
                Collections.unmodifiableMap(claims));
    }

    private static List<String> readAmr(Claims claims) {
        Object raw = claims.get(CLAIM_AMR);
        if (!(raw instanceof List<?> list)) {
            return List.of();
        }
        return list.stream().map(String::valueOf).toList();
    }

    private static Instant toInstant(Date date) {
        return date == null ? null : date.toInstant();
    }

    private static UUID requiredUuid(String value) {
        UUID parsed = optionalUuid(value);
        if (parsed == null) {
            throw new IdentityTokenException(IdentityTokenException.Reason.INVALID, "That token is not valid");
        }
        return parsed;
    }

    private static UUID optionalUuid(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException ex) {
            throw new IdentityTokenException(IdentityTokenException.Reason.INVALID, "That token is not valid");
        }
    }

    /** Unmodifiable view helper for tests and diagnostics. */
    static Map<String, Object> claimsOf(IdentityToken token) {
        return token.claims();
    }
}
