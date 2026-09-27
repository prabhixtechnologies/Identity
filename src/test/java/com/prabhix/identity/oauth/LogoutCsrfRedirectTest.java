package com.prabhix.identity.oauth;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.security.web.csrf.MissingCsrfTokenException;

import static org.mockito.Mockito.mock;

import static org.assertj.core.api.Assertions.assertThat;

class LogoutCsrfRedirectTest {

    @Test
    void bareLogoutPostMissingCsrfShowsConfirmationPage() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout");
        assertThat(LogoutCsrfRedirect.shouldShowConfirmationPage(request, new MissingCsrfTokenException("")))
                .isTrue();
    }

    @Test
    void bareLogoutPostInvalidCsrfShowsConfirmationPage() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout");
        CsrfToken token = mock(CsrfToken.class);
        assertThat(LogoutCsrfRedirect.shouldShowConfirmationPage(
                request, new InvalidCsrfTokenException(token, "mismatch")))
                .isTrue();
    }

    @Test
    void getLogoutIsNotTreatedAsCsrfFailure() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/logout");
        assertThat(LogoutCsrfRedirect.shouldShowConfirmationPage(request, new MissingCsrfTokenException("")))
                .isFalse();
    }
}
