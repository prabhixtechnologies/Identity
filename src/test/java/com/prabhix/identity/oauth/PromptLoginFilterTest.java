package com.prabhix.identity.oauth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class PromptLoginFilterTest {

    private final PromptLoginFilter filter = new PromptLoginFilter();

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("prompt=login drops the existing session and the prompt that would demand it again")
    void forcesLoginOnce() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oauth2/authorize");
        request.setQueryString("prompt=login&max_age=0&client_id=prabhix-admin");
        request.setParameter("prompt", "login");
        request.setParameter("max_age", "0");
        request.setParameter("client_id", "prabhix-admin");
        SecurityContextImpl context = new SecurityContextImpl(
                UsernamePasswordAuthenticationToken.authenticated("user", null, List.of()));
        SecurityContextHolder.setContext(context);
        request.getSession().setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(request.getSession().getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).isNull();
        ArgumentCaptor<HttpServletRequest> forwarded = ArgumentCaptor.forClass(HttpServletRequest.class);
        verify(chain).doFilter(forwarded.capture(), any());
        assertThat(forwarded.getValue().getParameter("prompt")).isNull();
        assertThat(forwarded.getValue().getParameter("max_age")).isNull();
        assertThat(forwarded.getValue().getParameter("client_id")).isEqualTo("prabhix-admin");
        assertThat(forwarded.getValue().getQueryString())
                .isEqualTo("client_id=prabhix-admin");
    }

    @Test
    @DisplayName("an authorize without prompt=login keeps the existing session")
    void leavesOrdinaryAuthorizeAlone() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oauth2/authorize");
        request.setParameter("client_id", "prabhix-admin");
        UsernamePasswordAuthenticationToken authentication =
                UsernamePasswordAuthenticationToken.authenticated("user", null, List.of());
        SecurityContextHolder.getContext().setAuthentication(authentication);
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(authentication);
        verify(chain).doFilter(eq(request), any(MockHttpServletResponse.class));
    }

    @Test
    void staffPasswordExplainsTheSecondFactor() {
        assertThat(LoginController.failureMessage("staff_mfa"))
                .contains("password is not enough")
                .doesNotContain("do not match");
    }
}
