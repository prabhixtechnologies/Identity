package com.prabhix.identity.oauth;

import com.prabhix.identity.config.IdentityProperties;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.UUID;

/**
 * Adds the durable browser session to Spring Security's password-login success path.
 *
 * <p>Passwordless, social and passkey methods complete through {@link HostedSignIn}; form login is
 * owned by Spring Security and therefore needs this success handler to reach the same session code.
 */
@Component
public class HostedAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final HostedBrowserSession browserSessions;
    private final SavedRequestAwareAuthenticationSuccessHandler delegate =
            new SavedRequestAwareAuthenticationSuccessHandler();

    public HostedAuthenticationSuccessHandler(HostedBrowserSession browserSessions,
                                              IdentityProperties properties) {
        this.browserSessions = browserSessions;
        delegate.setDefaultTargetUrl(properties.urls().console());
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {
        browserSessions.establish(UUID.fromString(authentication.getName()), request, response);
        delegate.onAuthenticationSuccess(request, response, authentication);
    }
}
