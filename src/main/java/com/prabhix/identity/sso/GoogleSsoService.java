package com.prabhix.identity.sso;

import tools.jackson.databind.JsonNode;
import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.config.IdentityProperties;
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
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Sign-in with a Google account. */
@Slf4j
@Service
@RequiredArgsConstructor
public class GoogleSsoService {

    private static final String TOKENINFO = "https://oauth2.googleapis.com/tokeninfo?id_token={token}";

    private final AuthIdentityRepository identities;
    private final CredentialService credentials;
    private final SignInService signIn;
    private final IdentityProperties properties;
    private final RestClient restClient = RestClient.create();

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

        JsonNode tokenInfo = fetchTokenInfo(idToken);

        // Without the audience check anyone could present a Google token minted for their own
        // application and be signed in as the address it names.
        if (!clientId.equals(text(tokenInfo, "aud"))) {
            throw invalidToken();
        }
        if (!"true".equalsIgnoreCase(text(tokenInfo, "email_verified"))) {
            throw ApiException.of(ErrorCode.EMAIL_NOT_VERIFIED, "Your Google email is not verified");
        }

        String subject = text(tokenInfo, "sub");
        String email = text(tokenInfo, "email");
        String name = text(tokenInfo, "name");
        if (subject == null || subject.isBlank() || email == null || email.isBlank()) {
            throw invalidToken();
        }

        IdentityUser user = linkOrCreate(subject, email, name, tokenInfo);
        credentials.resetLoginFailures(user);
        // Google has already told us the address is verified, so a user who arrives this way should
        // not be asked to prove it again.
        credentials.markEmailVerified(user.getId());
        return user;
    }

    private IdentityUser linkOrCreate(String subject, String email, String name, JsonNode tokenInfo) {
        Optional<AuthIdentity> existing =
                identities.findByProviderAndProviderSubject(AuthProvider.GOOGLE, subject);
        if (existing.isPresent()) {
            AuthIdentity identity = existing.get();
            identity.setLastLoginAt(Instant.now());
            // Kept current so an operator looking at the row sees the address the person uses now,
            // not the one they signed up with. The subject, not this, is what we match on.
            identity.setProviderEmail(email);
            identities.save(identity);
            return credentials.requireActive(identity.getUserId());
        }

        // Linking by address, which trusts Google's email_verified — checked above. Without that
        // check this would be an account takeover: claim any address on a Google tenant you control
        // and inherit the Prabhix account that already uses it.
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
        return user;
    }

    private JsonNode fetchTokenInfo(String idToken) {
        try {
            JsonNode body = restClient.get().uri(TOKENINFO, idToken).retrieve().body(JsonNode.class);
            if (body == null) {
                throw invalidToken();
            }
            return body;
        } catch (RestClientException ex) {
            // Google returns 400 for an expired or malformed token, so this is usually the caller's
            // problem; it is also what an outage looks like, hence the log line.
            log.debug("Google tokeninfo rejected an id_token: {}", ex.getMessage());
            throw invalidToken();
        }
    }

    private ApiException invalidToken() {
        return ApiException.of(ErrorCode.INVALID_CREDENTIALS, "That Google token is not valid");
    }

    private Map<String, Object> toProfileMap(JsonNode node) {
        Map<String, Object> profile = new HashMap<>();
        node.properties().forEach(entry -> profile.put(entry.getKey(), entry.getValue().asText()));
        return profile;
    }

    private String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value != null && !value.isNull() ? value.asText() : null;
    }
}
