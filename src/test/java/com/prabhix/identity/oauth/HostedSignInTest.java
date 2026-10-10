package com.prabhix.identity.oauth;

import com.prabhix.identity.config.TestProperties;
import com.prabhix.identity.event.AuthEventRecorder;
import com.prabhix.identity.user.IdentityUser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.authority.FactorGrantedAuthority;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class HostedSignInTest {

    @Test
    @DisplayName("passwordless hosted sign-in also establishes the durable browser session")
    void establishesDurableSessionForPasswordlessLogin() throws Exception {
        HostedBrowserSession browserSessions = mock(HostedBrowserSession.class);
        AuthEventRecorder events = mock(AuthEventRecorder.class);
        HostedSignIn signIn = new HostedSignIn(
                TestProperties.signing("", List.of()), events, browserSessions);

        UUID userId = UUID.randomUUID();
        IdentityUser user = new IdentityUser();
        user.setId(userId);
        user.setEmail("person@example.com");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession();
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(browserSessions.establish(userId, request, response, true)).thenReturn(UUID.randomUUID());

        signIn.completeAndRedirect(user, FactorGrantedAuthority.OTT_AUTHORITY, request, response);

        verify(browserSessions).establish(userId, request, response, true);
        assertThat(request.getSession(false)).isNotNull();
        assertThat(response.getRedirectedUrl()).isEqualTo("https://app.prabhixtechnologies.com");
    }
}
