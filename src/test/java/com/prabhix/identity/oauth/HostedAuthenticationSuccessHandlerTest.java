package com.prabhix.identity.oauth;

import com.prabhix.identity.config.TestProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class HostedAuthenticationSuccessHandlerTest {

    @Test
    @DisplayName("Spring password login establishes a durable session before redirecting")
    void establishesDurableSessionForPasswordLogin() throws Exception {
        HostedBrowserSession browserSessions = mock(HostedBrowserSession.class);
        HostedAuthenticationSuccessHandler handler = new HostedAuthenticationSuccessHandler(
                browserSessions, TestProperties.signing("", List.of()));
        UUID userId = UUID.randomUUID();
        UsernamePasswordAuthenticationToken authentication =
                UsernamePasswordAuthenticationToken.authenticated(userId.toString(), null, List.of());
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(request, response, authentication);

        verify(browserSessions).establish(userId, request, response);
        assertThat(response.getRedirectedUrl()).isEqualTo("https://app.prabhixtechnologies.com");
    }
}
