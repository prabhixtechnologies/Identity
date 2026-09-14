package com.prabhix.identity.oauth;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Which page an unauthenticated {@code /authorize} lands on.
 *
 * <p>Worth pinning because getting it wrong is invisible: sending a signup to the login page produces
 * a working page, and the only symptom is that people who meant to create an account do not.
 */
class SignInEntryPointTest {

    private static final String REDIRECT = "http://localhost:5176/auth/callback";

    private final SignInEntryPoint entryPoint = new SignInEntryPoint("/login", clients("prabhix-console", REDIRECT));

    @Test
    @DisplayName("an ordinary authorization request goes to the login page")
    void defaultsToLogin() {
        assertThat(target(authorize(null))).isEqualTo("/login");
    }

    @Test
    @DisplayName("prompt=create goes to the signup page")
    void createGoesToSignup() {
        assertThat(target(authorize("create"))).isEqualTo("/signup");
    }

    @Test
    @DisplayName("prompt is a space-delimited list, so create counts wherever it appears")
    void createAmongOtherPrompts() {
        assertThat(target(authorize("create login"))).isEqualTo("/signup");
        assertThat(target(authorize("login create"))).isEqualTo("/signup");
    }

    @Test
    @DisplayName("other prompt values are not signup")
    void otherPromptsGoToLogin() {
        // consent and select_account are ordinary OIDC prompts a client may send for its own reasons.
        // Treating anything non-empty as signup would send those people to create a second account.
        assertThat(target(authorize("consent"))).isEqualTo("/login");
        assertThat(target(authorize("select_account"))).isEqualTo("/login");
        assertThat(target(authorize(""))).isEqualTo("/login");
    }

    @Test
    @DisplayName("prompt=none without a session returns login_required to the registered redirect")
    void promptNoneReturnsLoginRequired() {
        MockHttpServletRequest request = authorize("none");
        request.setParameter("state", "abc");
        String target = target(request);
        assertThat(target).startsWith(REDIRECT);
        assertThat(target).contains("error=login_required");
        assertThat(target).contains("state=abc");
    }

    @Test
    @DisplayName("prompt=none with any other value is still an error, not a signup page")
    void promptNoneWinsOverCreate() {
        // OpenID Connect: none combined with any other prompt value is an error, not a page.
        assertThat(target(authorize("none create"))).contains("error=login_required");
    }

    @Test
    @DisplayName("prompt=none does not redirect to an unregistered URI")
    void promptNoneRejectsUnregisteredRedirect() {
        MockHttpServletRequest request = authorize("none");
        request.setParameter("redirect_uri", "https://evil.example/steal");
        assertThat(target(request)).isEqualTo("/login");
    }

    private static MockHttpServletRequest authorize(String prompt) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oauth2/authorize");
        request.setParameter("response_type", "code");
        request.setParameter("client_id", "prabhix-console");
        request.setParameter("redirect_uri", REDIRECT);
        if (prompt != null) {
            request.setParameter("prompt", prompt);
        }
        return request;
    }

    private String target(MockHttpServletRequest request) {
        return entryPoint.determineUrlToUseForThisRequest(request, new MockHttpServletResponse(), null);
    }

    private static RegisteredClientRepository clients(String clientId, String redirectUri) {
        RegisteredClient client = RegisteredClient.withId("test")
                .clientId(clientId)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(redirectUri)
                .scope("openid")
                .build();
        return new RegisteredClientRepository() {
            @Override
            public void save(RegisteredClient registeredClient) {
            }

            @Override
            public RegisteredClient findById(String id) {
                return null;
            }

            @Override
            public RegisteredClient findByClientId(String id) {
                return clientId.equals(id) ? client : null;
            }
        };
    }
}
