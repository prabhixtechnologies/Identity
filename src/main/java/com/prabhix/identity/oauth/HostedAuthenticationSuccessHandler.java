package com.prabhix.identity.oauth;

import com.prabhix.identity.config.IdentityProperties;
import com.prabhix.identity.session.StaffSignInPolicy;
import com.prabhix.identity.user.IdentityUser;
import com.prabhix.identity.user.IdentityUserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.List;
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
    private final IdentityUserRepository users;
    private final SavedRequestAwareAuthenticationSuccessHandler delegate =
            new SavedRequestAwareAuthenticationSuccessHandler();

    public HostedAuthenticationSuccessHandler(HostedBrowserSession browserSessions,
                                              IdentityUserRepository users,
                                              IdentityProperties properties) {
        this.browserSessions = browserSessions;
        this.users = users;
        delegate.setDefaultTargetUrl(properties.urls().console());
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {
        UUID userId = UUID.fromString(authentication.getName());
        IdentityUser user = users.findById(userId).orElse(null);
        if (!StaffSignInPolicy.allows(user, List.of(FactorGrantedAuthority.PASSWORD_AUTHORITY))) {
            SecurityContextHolder.clearContext();
            response.sendRedirect("/login?error=staff_mfa");
            return;
        }
        browserSessions.establish(userId, request, response);
        delegate.onAuthenticationSuccess(request, response, authentication);
    }
}
