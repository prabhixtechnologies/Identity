package com.prabhix.identity.token;

import com.prabhix.identity.config.IdentityProperties;
import com.prabhix.identity.jwks.SigningKey;
import com.prabhix.identity.jwks.SigningKeyProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.LocatorAdapter;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Signs access tokens, and verifies the ones it signed.
 *
 * <p>Verification lives here for this service's own protected endpoints and for the tests that prove
 * a token issued by the active key survives a rotation. Products do not call this — they verify
 * offline against the published JWKS, which is the point of RS256: a product never needs anything
 * from us that would also let it mint a token.
 */
@Service
@RequiredArgsConstructor
public class TokenService {

    /**
     * Standard OIDC claim names, spelled as the specification does so that Spring Security's
     * {@code JwtAuthenticationConverter} and any off-the-shelf client read them without mapping.
     */
    private static final String CLAIM_EMAIL = "email";
    private static final String CLAIM_EMAIL_VERIFIED = "email_verified";
    private static final String CLAIM_NAME = "name";
    private static final String CLAIM_SESSION_ID = "sid";
    private static final String CLAIM_AUTH_METHODS = "amr";

    private final SigningKeyProvider keys;
    private final IdentityProperties properties;

    public IssuedToken issue(IdentityClaims claims) {
        SigningKey key = keys.active();
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(properties.token().accessTokenTtl());

        String token = Jwts.builder()
                // The kid lets a client pick the right key out of the JWKS instead of trying each in
                // turn, which is what makes retiring a key take effect rather than merely stop being
                // preferred.
                .header().keyId(key.keyId()).and()
                .issuer(properties.issuer())
                .subject(claims.subject().toString())
                .id(UUID.randomUUID().toString())
                .issuedAt(Date.from(issuedAt))
                .expiration(Date.from(expiresAt))
                .claim(CLAIM_EMAIL, claims.email())
                .claim(CLAIM_EMAIL_VERIFIED, claims.emailVerified())
                .claim(CLAIM_NAME, claims.name())
                .claim(CLAIM_SESSION_ID, claims.sessionId().toString())
                .claim(CLAIM_AUTH_METHODS, claims.authenticationMethods())
                .signWith(key.privateKey(), Jwts.SIG.RS256)
                .compact();

        return new IssuedToken(token, expiresAt);
    }

    /**
     * @throws io.jsonwebtoken.JwtException if the token is expired, malformed, signed by a key we do
     *     not publish, or issued by a different issuer
     */
    public IdentityClaims verify(String token) {
        return verified(token).claims();
    }

    /**
     * Verifies and also returns {@code iat}.
     *
     * <p>Separate from {@link #verify} because only the deny-list check needs the issue time — a
     * user-scoped revocation denies tokens minted before it and lets later ones through — and every
     * other caller would have to ignore the extra field.
     *
     * @throws io.jsonwebtoken.JwtException as {@link #verify}
     */
    public VerifiedToken verified(String token) {
        Jws<Claims> jws = Jwts.parser()
                .keyLocator(new LocatorAdapter<Key>() {
                    @Override
                    protected Key locate(JwsHeader header) {
                        return keys.verificationKey(header.getKeyId())
                                .orElseThrow(() -> new SignatureException(
                                        "Token names key id " + header.getKeyId()
                                                + ", which this issuer does not publish"));
                    }
                })
                // Without this, a token signed by us for a different deployment — staging's key
                // rotated into production's retired list, say — would verify here.
                .requireIssuer(properties.issuer())
                .build()
                .parseSignedClaims(token);

        Claims claims = jws.getPayload();
        IdentityClaims identity = new IdentityClaims(
                UUID.fromString(claims.getSubject()),
                claims.get(CLAIM_EMAIL, String.class),
                Boolean.TRUE.equals(claims.get(CLAIM_EMAIL_VERIFIED, Boolean.class)),
                claims.get(CLAIM_NAME, String.class),
                UUID.fromString(claims.get(CLAIM_SESSION_ID, String.class)),
                authenticationMethods(claims));
        Date issuedAt = claims.getIssuedAt();
        return new VerifiedToken(identity, issuedAt == null ? null : issuedAt.toInstant());
    }

    /** @param issuedAt null for a token that carries no {@code iat}, which the deny list treats as old */
    public record VerifiedToken(IdentityClaims claims, Instant issuedAt) {
    }

    @SuppressWarnings("unchecked")
    private List<String> authenticationMethods(Claims claims) {
        Object amr = claims.get(CLAIM_AUTH_METHODS);
        return amr instanceof List<?> list ? List.copyOf((List<String>) list) : List.of();
    }

    /**
     * @param expiresAt returned alongside the token so a client does not have to decode it to learn
     *     when to refresh, which is the only reason a client would ever parse an opaque-to-it token
     */
    public record IssuedToken(String token, Instant expiresAt) {
    }
}
