package com.prabhix.identity.oauth;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Which product's colours the hosted pages wear.
 *
 * <p>The mapping itself is dull; the fallbacks are not. This value becomes a {@code data-brand}
 * attribute in the document, and it is derived from a {@code client_id} that arrives in a query
 * string anyone can write. The tests that matter here are the ones asserting that an unrecognised
 * or hostile client id produces a known literal rather than being echoed.
 */
class SignInBrandTest {

    private final SignInBrand brands = new SignInBrand();

    @Test
    @DisplayName("each product's web and Android clients resolve to the same brand")
    void webAndAndroidAgree() {
        assertThat(brandFor("prabhix-console")).isEqualTo("oneops");
        assertThat(brandFor("prabhix-oneops-android")).isEqualTo("oneops");
        assertThat(brandFor("prabhix-mailroom")).isEqualTo("mailroom");
        assertThat(brandFor("prabhix-mailroom-android")).isEqualTo("mailroom");
        assertThat(brandFor("prabhix-mobistack")).isEqualTo("mobistack");
        assertThat(brandFor("prabhix-mobistack-android")).isEqualTo("mobistack");
        assertThat(brandFor("prabhix-admin")).isEqualTo("admin");
        assertThat(brandFor("prabhix-admin-android")).isEqualTo("admin");
    }

    @Test
    @DisplayName("no pending authorization request falls back to the house brand")
    void noSavedRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        assertThat(brands.forRequest(request, new MockHttpServletResponse())).isEqualTo(SignInBrand.HOUSE);
    }

    @Test
    @DisplayName("an unregistered client id falls back rather than being echoed")
    void unknownClient() {
        assertThat(brandFor("some-other-app")).isEqualTo(SignInBrand.HOUSE);
    }

    @Test
    @DisplayName("a client id crafted to break out of the attribute is never returned")
    void hostileClientId() {
        // The failure this guards against is returning the input at all. If it were echoed, this
        // value would close data-brand and open a script tag on every hosted page.
        String injection = "\"><script>alert(1)</script>";
        assertThat(brandFor(injection)).isEqualTo(SignInBrand.HOUSE).doesNotContain("script");
    }

    @Test
    @DisplayName("reading the brand does not consume the saved request")
    void doesNotConsumeSavedRequest() {
        // The same saved request still has to redirect the person onward after they sign in.
        MockHttpServletRequest request = authorizeRequest("prabhix-mailroom");
        MockHttpServletResponse response = new MockHttpServletResponse();

        brands.forRequest(request, response);

        assertThat(new HttpSessionRequestCache().getRequest(request, response)).isNotNull();
        assertThat(brands.forRequest(request, response)).isEqualTo("mailroom");
    }

    private String brandFor(String clientId) {
        return brands.forRequest(authorizeRequest(clientId), new MockHttpServletResponse());
    }

    /** A session holding the /authorize request that Spring Security saved before redirecting. */
    private MockHttpServletRequest authorizeRequest(String clientId) {
        MockHttpServletRequest authorize = new MockHttpServletRequest("GET", "/oauth2/authorize");
        authorize.setParameter("client_id", clientId);
        authorize.setParameter("response_type", "code");

        MockHttpServletResponse response = new MockHttpServletResponse();
        new HttpSessionRequestCache().saveRequest(authorize, response);

        MockHttpServletRequest login = new MockHttpServletRequest("GET", "/login");
        login.setSession(authorize.getSession());
        return login;
    }
}
