package com.prabhix.identity.jwks;

import com.prabhix.identity.config.IdentityProperties;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.RsaPublicJwk;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Holds the key this service signs with, and every key whose signatures are still worth verifying.
 *
 * <p>The platform signs HS256 with a shared secret today. Across services that is the wrong shape:
 * verifying a token and minting one become the same capability, so any service handed the secret in
 * order to check a token could equally issue itself an administrator's. RS256 splits them — this
 * service holds the private key, and products get a public key they can only verify with.
 */
@Slf4j
@Component
public class SigningKeyProvider {

    private static final Set<String> LOCAL_PROFILES = Set.of("dev", "test", "local");
    private static final int MIN_KEY_BITS = 2048;

    private final SigningKey active;
    private final List<RsaPublicJwk> published;

    public SigningKeyProvider(IdentityProperties properties, Environment environment) {
        String configured = properties.signing().privateKey();
        this.active = (configured == null || configured.isBlank())
                ? ephemeralKey(environment)
                : configuredKey(configured);

        List<RsaPublicJwk> jwks = new ArrayList<>();
        jwks.add(jwk(active.publicKey()));
        for (String retired : retiredKeys(properties)) {
            jwks.add(jwk(Pem.publicKey(retired)));
        }
        this.published = List.copyOf(jwks);

        log.info("Signing with RS256, key id {}; publishing {} key(s) in the JWKS",
                active.keyId(), published.size());
    }

    /** The key to sign new tokens with. */
    public SigningKey active() {
        return active;
    }

    /**
     * Every key to publish, active first.
     *
     * <p>Retired keys stay here through a rotation because a product caches the JWKS and access
     * tokens outlive the switch: drop the old key at the moment the new one starts signing and every
     * token issued in the previous fifteen minutes stops verifying.
     */
    public List<RsaPublicJwk> published() {
        return published;
    }

    /**
     * The public key a token's {@code kid} header names, if it is one of ours.
     *
     * <p>Looked up by key id rather than tried in turn: verifying against every published key would
     * mean a token signed by a retired key still verifies after the key is removed from this list on
     * the next deploy, which is the one thing retiring a key is supposed to prevent.
     */
    public Optional<RSAPublicKey> verificationKey(String keyId) {
        if (keyId == null) {
            return Optional.empty();
        }
        return published.stream()
                .filter(jwk -> keyId.equals(jwk.getId()))
                .<RSAPublicKey>map(RsaPublicJwk::toKey)
                .findFirst();
    }

    private SigningKey configuredKey(String pem) {
        RSAPrivateKey privateKey = Pem.privateKey(pem);
        if (privateKey.getModulus().bitLength() < MIN_KEY_BITS) {
            throw new IllegalStateException("Signing key is "
                    + privateKey.getModulus().bitLength() + " bits; RS256 needs at least "
                    + MIN_KEY_BITS);
        }
        return new SigningKey(privateKey, derivePublicKey(privateKey));
    }

    /**
     * A key generated at startup, for a developer who has not configured one.
     *
     * <p>Refused outside a local profile, mirroring the platform's JWT secret check. It would
     * otherwise appear to work: tokens sign and verify happily until the process restarts, at which
     * point every issued token becomes unverifiable and every signed-in user is logged out — and
     * with more than one replica, tokens from one instance never verify against another at all.
     */
    private SigningKey ephemeralKey(Environment environment) {
        String[] active = environment.getActiveProfiles();
        boolean local = active.length == 0
                || Arrays.stream(active).anyMatch(LOCAL_PROFILES::contains);
        if (!local) {
            throw new IllegalStateException("IDENTITY_SIGNING_KEY is not set. Generate one with: "
                    + "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048");
        }

        log.warn("No signing key configured, generating an ephemeral one. Every token issued now "
                + "becomes invalid when this process restarts.");
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(MIN_KEY_BITS);
            KeyPair pair = generator.generateKeyPair();
            return new SigningKey((RSAPrivateKey) pair.getPrivate(), (RSAPublicKey) pair.getPublic());
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("This JVM cannot generate RSA keys", ex);
        }
    }

    /**
     * An RSA private key already contains its public exponent, so the public half needs no separate
     * configuration and cannot drift out of step with the private one.
     */
    private RSAPublicKey derivePublicKey(RSAPrivateKey privateKey) {
        if (!(privateKey instanceof RSAPrivateCrtKey crt)) {
            throw new IllegalStateException("Signing key carries no public exponent, so the public "
                    + "key cannot be derived from it. Re-export it as a standard PKCS#8 RSA key.");
        }
        try {
            return (RSAPublicKey) java.security.KeyFactory.getInstance("RSA")
                    .generatePublic(new RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent()));
        } catch (Exception ex) {
            throw new IllegalStateException("Could not derive the public key from the signing key", ex);
        }
    }

    private List<String> retiredKeys(IdentityProperties properties) {
        List<String> retired = properties.signing().retiredPublicKeys();
        return retired == null ? List.of() : retired.stream().filter(k -> !k.isBlank()).toList();
    }

    /**
     * The key id is the RFC 7638 thumbprint of the key itself rather than a name someone chose. It
     * is therefore stable across restarts and redeploys for the same key, and necessarily different
     * for a different key — so a rotation cannot accidentally reuse an id and leave clients
     * verifying against the wrong half of a pair.
     */
    private RsaPublicJwk jwk(RSAPublicKey publicKey) {
        return Jwks.builder()
                .key(publicKey)
                .idFromThumbprint()
                .algorithm("RS256")
                .publicKeyUse("sig")
                .build();
    }
}
