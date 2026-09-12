package com.prabhix.identity.webauthn;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.config.IdentityProperties;
import com.prabhix.identity.user.CredentialService;
import com.prabhix.identity.user.IdentityUser;
import com.prabhix.identity.user.IdentityUserRepository;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.AttestationConveyancePreference;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticatorSelectionCriteria;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.PublicKeyCredentialCreationOptions;
import com.webauthn4j.data.PublicKeyCredentialDescriptor;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialRequestOptions;
import com.webauthn4j.data.PublicKeyCredentialRpEntity;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.PublicKeyCredentialUserEntity;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.ResidentKeyRequirement;
import com.webauthn4j.data.UserVerificationRequirement;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.verifier.exception.VerificationException;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Passkey registration and assertion.
 *
 * <p>Challenges for hosted login live in the HTTP session (the browser already has one on this
 * chain). Registration challenges for the bearer API live in a short-lived in-memory map, because
 * that chain is deliberately sessionless — a second secret in Redis would be right at scale, but a
 * single-node map matches how Identity runs today.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class WebAuthnService {

    private static final String SESSION_ASSERTION_CHALLENGE = "webauthn.assertion.challenge";
    private static final long PENDING_TTL_SECONDS = 300;

    private static final List<PublicKeyCredentialParameters> PUB_KEY_PARAMS = List.of(
            new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
            new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256));

    private final IdentityProperties properties;
    private final WebAuthnCredentialRepository credentials;
    private final IdentityUserRepository users;
    private final CredentialService credentialService;
    private final ObjectConverter objectConverter = new ObjectConverter();
    private final WebAuthnManager webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);
    private final ConcurrentHashMap<UUID, PendingChallenge> registrationChallenges = new ConcurrentHashMap<>();

    /** Options for {@code navigator.credentials.create}, for an already-authenticated caller. */
    public Map<String, Object> beginRegistration(UUID userId) {
        IdentityUser user = credentialService.requireActive(userId);
        purgeExpiredRegistrationChallenges();

        Challenge challenge = new DefaultChallenge();
        registrationChallenges.put(userId, new PendingChallenge(challenge.getValue(), Instant.now()));

        List<PublicKeyCredentialDescriptor> exclude = credentials.findByUserId(userId).stream()
                .map(cred -> new PublicKeyCredentialDescriptor(
                        PublicKeyCredentialType.PUBLIC_KEY,
                        cred.getCredentialId(),
                        transportsOf(cred)))
                .toList();

        byte[] userHandle = uuidBytes(user.getId());
        PublicKeyCredentialCreationOptions options = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(properties.webAuthn().rpId(), properties.webAuthn().rpName()),
                new PublicKeyCredentialUserEntity(userHandle, user.getEmail(), user.effectiveDisplayName()),
                challenge,
                PUB_KEY_PARAMS,
                120_000L,
                exclude,
                new AuthenticatorSelectionCriteria(
                        null,
                        ResidentKeyRequirement.PREFERRED,
                        UserVerificationRequirement.PREFERRED),
                AttestationConveyancePreference.NONE,
                null);

        return objectConverter.getJsonConverter().readValue(
                objectConverter.getJsonConverter().writeValueAsString(options), Map.class);
    }

    @Transactional
    public void finishRegistration(UUID userId, String registrationResponseJson, String label) {
        PendingChallenge pending = registrationChallenges.remove(userId);
        if (pending == null || pending.expired()) {
            throw ApiException.of(ErrorCode.OTP_EXPIRED, "That passkey registration has expired. Try again.");
        }

        RegistrationData registrationData;
        try {
            registrationData = webAuthnManager.parseRegistrationResponseJSON(registrationResponseJson);
        } catch (DataConversionException ex) {
            throw ApiException.of(ErrorCode.MALFORMED_REQUEST, "That passkey response could not be read");
        }

        try {
            webAuthnManager.verify(registrationData, new RegistrationParameters(
                    serverProperty(new DefaultChallenge(pending.challenge())),
                    PUB_KEY_PARAMS,
                    false,
                    true));
        } catch (VerificationException ex) {
            log.debug("Passkey registration rejected: {}", ex.getMessage());
            throw ApiException.of(ErrorCode.INVALID_CREDENTIALS, "Those details do not match an account.");
        }

        AttestedCredentialData attested = registrationData.getAttestationObject()
                .getAuthenticatorData()
                .getAttestedCredentialData();
        if (attested == null) {
            throw ApiException.of(ErrorCode.MALFORMED_REQUEST, "That passkey response was incomplete");
        }

        if (credentials.findByCredentialId(attested.getCredentialId()).isPresent()) {
            throw ApiException.of(ErrorCode.CONFLICT, "That passkey is already registered");
        }

        WebAuthnCredential row = new WebAuthnCredential();
        row.setUserId(userId);
        row.setCredentialId(attested.getCredentialId());
        row.setPublicKey(objectConverter.getCborConverter().writeValueAsBytes(attested.getCOSEKey()));
        row.setSignatureCount(registrationData.getAttestationObject().getAuthenticatorData().getSignCount());
        row.setAaguid(aaguidUuid(attested.getAaguid()));
        row.setLabel(label == null || label.isBlank() ? "Passkey" : label.trim());
        row.setTransports(transportStrings(registrationData.getTransports()));
        credentials.save(row);
    }

    /**
     * Options for {@code navigator.credentials.get}.
     *
     * <p>When an email is supplied (the choose stage), allowCredentials is limited to that account's
     * passkeys so non-discoverable authenticators still work. Without one, allowCredentials is empty
     * and the browser offers discoverable credentials only — which reveals nothing about membership.
     */
    public Map<String, Object> beginAssertion(String email, HttpSession session) {
        Challenge challenge = new DefaultChallenge();
        session.setAttribute(SESSION_ASSERTION_CHALLENGE, challenge.getValue());

        List<PublicKeyCredentialDescriptor> allow = List.of();
        if (email != null && !email.isBlank()) {
            allow = users.findActiveByEmail(email)
                    .map(user -> credentials.findByUserId(user.getId()).stream()
                            .map(cred -> new PublicKeyCredentialDescriptor(
                                    PublicKeyCredentialType.PUBLIC_KEY,
                                    cred.getCredentialId(),
                                    transportsOf(cred)))
                            .toList())
                    .orElse(List.of());
            // Same shape whether or not the address has passkeys, so the options call is not an
            // enumeration oracle for "does this email have an account with a passkey".
        }

        PublicKeyCredentialRequestOptions options = new PublicKeyCredentialRequestOptions(
                challenge,
                120_000L,
                properties.webAuthn().rpId(),
                allow,
                UserVerificationRequirement.PREFERRED,
                null);

        return objectConverter.getJsonConverter().readValue(
                objectConverter.getJsonConverter().writeValueAsString(options), Map.class);
    }

    @Transactional
    public IdentityUser finishAssertion(String authenticationResponseJson, HttpSession session) {
        byte[] expected = (byte[]) session.getAttribute(SESSION_ASSERTION_CHALLENGE);
        session.removeAttribute(SESSION_ASSERTION_CHALLENGE);
        if (expected == null) {
            throw ApiException.of(ErrorCode.OTP_EXPIRED, "That passkey sign-in has expired. Try again.");
        }

        AuthenticationData authenticationData;
        try {
            authenticationData = webAuthnManager.parseAuthenticationResponseJSON(authenticationResponseJson);
        } catch (DataConversionException ex) {
            throw ApiException.of(ErrorCode.MALFORMED_REQUEST, "That passkey response could not be read");
        }

        WebAuthnCredential stored = credentials.findByCredentialId(authenticationData.getCredentialId())
                .orElseThrow(() -> ApiException.of(ErrorCode.INVALID_CREDENTIALS,
                        "Those details do not match an account."));

        CredentialRecord record = toCredentialRecord(stored);
        try {
            webAuthnManager.verify(authenticationData, new AuthenticationParameters(
                    serverProperty(new DefaultChallenge(expected)),
                    record,
                    null,
                    true,
                    true));
        } catch (VerificationException ex) {
            log.debug("Passkey assertion rejected: {}", ex.getMessage());
            throw ApiException.of(ErrorCode.INVALID_CREDENTIALS, "Those details do not match an account.");
        }

        long newCount = authenticationData.getAuthenticatorData().getSignCount();
        // Zero stays zero for authenticators that do not increment; anything else must not go backwards.
        if (newCount > 0 && newCount <= stored.getSignatureCount()) {
            throw ApiException.of(ErrorCode.INVALID_CREDENTIALS, "Those details do not match an account.");
        }
        stored.setSignatureCount(newCount);
        credentials.save(stored);

        IdentityUser user = credentialService.requireActive(stored.getUserId());
        credentialService.resetLoginFailures(user);
        return user;
    }

    private ServerProperty serverProperty(Challenge challenge) {
        Set<Origin> origins = properties.webAuthn().origins().stream()
                .filter(o -> o != null && !o.isBlank())
                .map(Origin::new)
                .collect(Collectors.toSet());
        if (origins.isEmpty()) {
            throw new IllegalStateException("prabhix.identity.web-authn.origins must not be empty");
        }
        return ServerProperty.builder()
                .origins(origins)
                .rpId(properties.webAuthn().rpId())
                .challenge(challenge)
                .build();
    }

    private CredentialRecord toCredentialRecord(WebAuthnCredential stored) {
        COSEKey coseKey = objectConverter.getCborConverter().readValue(stored.getPublicKey(), COSEKey.class);
        AAGUID aaguid = stored.getAaguid() == null
                ? AAGUID.NULL
                : new AAGUID(uuidBytes(stored.getAaguid()));
        AttestedCredentialData attested = new AttestedCredentialData(aaguid, stored.getCredentialId(), coseKey);
        Set<AuthenticatorTransport> transports = stored.getTransports() == null
                ? Set.of()
                : stored.getTransports().stream()
                        .map(AuthenticatorTransport::create)
                        .collect(Collectors.toSet());
        return new CredentialRecordImpl(
                null,
                null,
                null,
                null,
                stored.getSignatureCount(),
                attested,
                null,
                null,
                null,
                transports);
    }

    private static Set<AuthenticatorTransport> transportsOf(WebAuthnCredential cred) {
        if (cred.getTransports() == null || cred.getTransports().isEmpty()) {
            return null;
        }
        return cred.getTransports().stream()
                .map(AuthenticatorTransport::create)
                .collect(Collectors.toSet());
    }

    private static List<String> transportStrings(Set<AuthenticatorTransport> transports) {
        if (transports == null || transports.isEmpty()) {
            return new ArrayList<>();
        }
        return transports.stream().map(AuthenticatorTransport::getValue).sorted().toList();
    }

    private static UUID aaguidUuid(AAGUID aaguid) {
        if (aaguid == null || aaguid.equals(AAGUID.NULL) || aaguid.getBytes() == null) {
            return null;
        }
        byte[] bytes = aaguid.getBytes();
        if (bytes.length != 16) {
            return null;
        }
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        return new UUID(buffer.getLong(), buffer.getLong());
    }

    private static byte[] uuidBytes(UUID id) {
        ByteBuffer buffer = ByteBuffer.allocate(16);
        buffer.putLong(id.getMostSignificantBits());
        buffer.putLong(id.getLeastSignificantBits());
        return buffer.array();
    }

    private void purgeExpiredRegistrationChallenges() {
        Instant cutoff = Instant.now().minusSeconds(PENDING_TTL_SECONDS);
        registrationChallenges.entrySet().removeIf(e -> e.getValue().createdAt().isBefore(cutoff));
    }

    private record PendingChallenge(byte[] challenge, Instant createdAt) {
        boolean expired() {
            return createdAt.isBefore(Instant.now().minusSeconds(PENDING_TTL_SECONDS));
        }
    }
}
