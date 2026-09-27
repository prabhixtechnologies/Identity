package com.prabhix.identity.security.internal;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

class InternalRoutePolicyTest {

    @Test
    void adminRoutesRequireActingUser() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/internal/identity/admin/users");
        assertThat(InternalRoutePolicy.requiresActingUser(request)).isTrue();
        assertThat(InternalRoutePolicy.isAutomatedServiceRoute(request)).isFalse();
    }

    @Test
    void automatedRoutesAreDocumentedPostPaths() {
        assertThat(InternalRoutePolicy.isAutomatedServiceRoute(
                new MockHttpServletRequest("POST", "/internal/identity/users/lookup"))).isTrue();
        assertThat(InternalRoutePolicy.isAutomatedServiceRoute(
                new MockHttpServletRequest("POST", "/internal/identity/users/revoke-tokens"))).isTrue();
        assertThat(InternalRoutePolicy.isAutomatedServiceRoute(
                new MockHttpServletRequest("POST", "/internal/identity/sessions/revoke-all"))).isTrue();
    }

    @Test
    void automatedRoutesDoNotRequireGet() {
        assertThat(InternalRoutePolicy.isAutomatedServiceRoute(
                new MockHttpServletRequest("GET", "/internal/identity/users/lookup"))).isFalse();
    }
}
