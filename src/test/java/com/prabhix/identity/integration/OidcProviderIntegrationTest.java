package com.prabhix.identity.integration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Proves this process actually is an OpenID provider, rather than merely containing the dependency.
 *
 * <p>Every assertion here is about wiring that fails silently. Three filter chains have to be ordered
 * so the stateless API chain does not swallow {@code /authorize}; the JWKS has to be served from the
 * path products are already configured with rather than Spring's default; and the seeded clients have
 * to come out of configuration with PKCE mandatory. Each of those looks fine at startup and breaks the
 * first time somebody tries to sign in.
 */
@Tag("integration")
@Testcontainers
@SpringBootTest
@AutoConfigureMockMvc
class OidcProviderIntegrationTest {

    private static final String ISSUER = "https://id.prabhixtechnologies.test";

    @Container
    @SuppressWarnings("resource")
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("prabhix_identity_oidc_test");

    @DynamicPropertySource
    static void configuration(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.profiles.active", () -> "dev");
        registry.add("prabhix.identity.issuer", () -> ISSUER);
    }

    @Autowired
    private MockMvc mvc;

    @Autowired
    private RegisteredClientRepository clients;

    @Test
    @DisplayName("discovery advertises the authorization code flow at the configured issuer")
    void discoveryDocument() throws Exception {
        mvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value(ISSUER))
                .andExpect(jsonPath("$.authorization_endpoint").value(ISSUER + "/oauth2/authorize"))
                .andExpect(jsonPath("$.token_endpoint").value(ISSUER + "/oauth2/token"))
                .andExpect(jsonPath("$.userinfo_endpoint").value(ISSUER + "/userinfo"))
                .andExpect(jsonPath("$.end_session_endpoint").value(ISSUER + "/connect/logout"))
                // The whole point of the move. A client library reads this to decide it can redirect
                // rather than post a password, and the previous hand-written document said it could not.
                .andExpect(jsonPath("$.grant_types_supported").value(
                        org.hamcrest.Matchers.hasItem("authorization_code")))
                .andExpect(jsonPath("$.code_challenge_methods_supported").value(
                        org.hamcrest.Matchers.hasItem("S256")));
    }

    @Test
    @DisplayName("the JWKS stays on /.well-known/jwks.json, where products already look for it")
    void jwksServedFromTheExistingPath() throws Exception {
        // Spring's default is /oauth2/jwks. Letting it move would mean reconfiguring every product to
        // keep verifying tokens it was already verifying, for nothing.
        mvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(jsonPath("$.jwks_uri").value(ISSUER + "/.well-known/jwks.json"));

        mvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].kid").exists())
                // d is the private exponent. Serving it would hand every reader the ability to mint
                // tokens as anyone.
                .andExpect(jsonPath("$.keys[0].d").doesNotExist());
    }

    @Test
    @DisplayName("a browser reaching /authorize unauthenticated is sent to the hosted login page")
    void authorizeRedirectsToLogin() throws Exception {
        mvc.perform(get("/oauth2/authorize")
                        .queryParam("response_type", "code")
                        .queryParam("client_id", "prabhix-console")
                        .queryParam("redirect_uri", "http://localhost:5173/auth/callback")
                        .queryParam("scope", "openid profile email")
                        .queryParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                        .queryParam("code_challenge_method", "S256")
                        .accept(org.springframework.http.MediaType.TEXT_HTML))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/login"));
    }

    @Test
    @DisplayName("/authorize without PKCE is refused for a public client")
    void pkceIsMandatory() throws Exception {
        // Without this, an intercepted redirect is enough to redeem the code, because a public client
        // has no secret standing between the attacker and the token endpoint.
        mvc.perform(get("/oauth2/authorize")
                        .queryParam("response_type", "code")
                        .queryParam("client_id", "prabhix-console")
                        .queryParam("redirect_uri", "http://localhost:5173/auth/callback")
                        .queryParam("scope", "openid")
                        .accept(org.springframework.http.MediaType.TEXT_HTML))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location",
                        org.hamcrest.Matchers.containsString("error=invalid_request")));
    }

    @Test
    @DisplayName("an unregistered redirect URI is refused rather than redirected to")
    void redirectUriIsMatchedExactly() throws Exception {
        // A prefix or wildcard match here would be an open redirect on the authorization endpoint,
        // which hands the code to whoever crafted the link. Spring refuses to redirect the error back
        // to an unregistered URI, so this is a 400 rather than a redirect carrying the error.
        mvc.perform(get("/oauth2/authorize")
                        .queryParam("response_type", "code")
                        .queryParam("client_id", "prabhix-console")
                        .queryParam("redirect_uri", "http://localhost:5173/auth/callback.evil.example")
                        .queryParam("scope", "openid")
                        .queryParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                        .queryParam("code_challenge_method", "S256")
                        .accept(org.springframework.http.MediaType.TEXT_HTML))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("configured clients are seeded as public clients requiring PKCE, with no consent")
    void clientsAreSeededFromConfiguration() throws Exception {
        for (String clientId : new String[]{
                "prabhix-console", "prabhix-admin",
                "prabhix-oneops-android", "prabhix-admin-android"}) {
            RegisteredClient client = clients.findByClientId(clientId);
            assertThat(client).as("client %s should be seeded", clientId).isNotNull();
            assertThat(client.getClientSettings().isRequireProofKey())
                    .as("%s must require PKCE", clientId).isTrue();
            // First-party: asking somebody to authorise Prabhix to access Prabhix is noise, and
            // training people to click through consent screens is a hazard of its own.
            assertThat(client.getClientSettings().isRequireAuthorizationConsent())
                    .as("%s should not prompt for consent", clientId).isFalse();
            assertThat(client.getScopes()).contains("openid");
        }
    }

    @Test
    @DisplayName("an unauthenticated API call still gets a JSON 401, not a redirect to the login page")
    void apiChainStillAnswers() throws Exception {
        // The regression this guards: give the authorization server's chain too broad a matcher, or
        // order the API chain after it, and every existing endpoint starts answering a browser
        // redirect. A client parsing JSON would see a 302 to HTML and report it as the API being down.
        mvc.perform(get("/api/v1/auth/sessions"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
    }
}
