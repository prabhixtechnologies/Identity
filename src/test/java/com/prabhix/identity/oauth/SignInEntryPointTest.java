package com.prabhix.identity.oauth;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Which page an unauthenticated {@code /authorize} lands on.
 *
 * <p>Worth pinning because getting it wrong is invisible: sending a signup to the login page produces
 * a working page, and the only symptom is that people who meant to create an account do not.
 */
class SignInEntryPointTest {

    private final SignInEntryPoint entryPoint = new SignInEntryPoint("/login");

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

    private static MockHttpServletRequest authorize(String prompt) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oauth2/authorize");
        request.setParameter("response_type", "code");
        request.setParameter("client_id", "prabhix-console");
        if (prompt != null) {
            request.setParameter("prompt", prompt);
        }
        return request;
    }

    private String target(MockHttpServletRequest request) {
        return entryPoint.determineUrlToUseForThisRequest(request, new MockHttpServletResponse(), null);
    }
}
