package com.prabhix.identity.sso;

import tools.jackson.databind.JsonNode;
import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.config.IdentityProperties;
import com.prabhix.identity.event.AuthEventRecorder;
import com.prabhix.identity.event.AuthEventType;
import com.prabhix.identity.session.SessionService.DeviceContext;
import com.prabhix.identity.session.SignInService;
import com.prabhix.identity.user.AuthIdentity;
import com.prabhix.identity.user.AuthIdentity.AuthProvider;
import com.prabhix.identity.user.AuthIdentityRepository;
import com.prabhix.identity.user.CredentialService;
import com.prabhix.identity.user.IdentityUser;
import com.prabhix.identity.web.AuthDtos.TokenResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.prabhix.identity.event.AuthEventRecorder.details;

/** Sign-in with a Google account. */
@Slf4j
@Service
@RequiredArgsConstructor
public class GoogleSsoService {

    private final AuthIdentityRepository identities;
    private final CredentialService credentials;
    private final SignInService signIn;
    private final IdentityProperties properties;
    private final AuthEventRecorder events;
    private final GoogleIdTokenVerifier idTokenVerifier;

    /** Whether a client id is configured, which decides if the login page offers the button. */
    public boolean enabled() {
        String clientId = properties.sso().googleClientId();
        return clientId != null && !clientId.isBlank();
    }

    /** The client id the browser needs to render Google's own button. Not a secret. */
    public String clientId() {
        return properties.sso().googleClientId();
    }

    @Transactional
    public TokenResponse authenticate(String idToken, DeviceContext device) {
        return signIn.complete(authenticate(idToken), device, List.of("google"));
    }

    /**
     * Verifies a Google {@code id_token} and returns the matching user, issuing nothing.
     *
     * <p>Split out for the hosted login page, which needs a browser session rather than tokens.
     */
    @Transactional
    public IdentityUser authenticate(String idToken) {
        String clientId = properties.sso().googleClientId();
        if (clientId == null || clientId.isBlank()) {
            throw ApiException.of(ErrorCode.FEATURE_DISABLED, "Google sign-in is not enabled");
        }

        GoogleIdTokenVerifier.Verified verified = idTokenVerifier.verify(idToken, clientId);
        String subject = verified.subject();
        String email = verified.email();
        String name = verified.name();
        if (subject == null || subject.isBlank() || email == null || email.isBlank()) {
            throw invalidToken();
        }

        IdentityUser user = linkOrCreate(subject, email, name, verified.tokenInfoProfile());
        credentials.ensureSignInAllowed(user);
        credentials.resetLoginFailures(user);
        credentials.markEmailVerified(user.getId());
        return user;
    }

    private IdentityUser linkOrCreate(String subject, String email, String name, JsonNode tokenInfo) {
        Optional<AuthIdentity> existing =
                identities.findByProviderAndProviderSubject(AuthProvider.GOOGLE, subject);
        if (existing.isPresent()) {
            AuthIdentity identity = existing.get();
            identity.setLastLoginAt(Instant.now());
            identity.setProviderEmail(email);
            identities.save(identity);
            return credentials.requireActive(identity.getUserId());
        }

        IdentityUser user = credentials.findByEmail(email)
                .orElseGet(() -> credentials.createPasswordless(
                        email, name != null && !name.isBlank() ? name : email));

        AuthIdentity identity = new AuthIdentity();
        identity.setUserId(user.getId());
        identity.setProvider(AuthProvider.GOOGLE);
        identity.setProviderSubject(subject);
        identity.setProviderEmail(email);
        identity.setRawProfile(toProfileMap(tokenInfo));
        identity.setLastLoginAt(Instant.now());
        identities.save(identity);
        events.success(AuthEventType.GOOGLE_LINKED, user.getId(), user.getEmail(),
                details("providerEmail", email, "how", "sign_in"));
        return user;
    }

    private ApiException invalidToken() {
        return ApiException.of(ErrorCode.INVALID_CREDENTIALS, "That Google token is not valid");
    }

    private Map<String, Object> toProfileMap(JsonNode node) {
        if (node == null) {
            return Map.of();
        }
        Map<String, Object> profile = new HashMap<>();
        node.properties().forEach(entry -> profile.put(entry.getKey(), entry.getValue().asText()));
        return profile;
    }
}
