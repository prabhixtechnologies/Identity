package com.prabhix.identity.oauth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Returns a failed password attempt to the step it was made on, with the address still filled in.
 *
 * <p>Spring Security's default sends everything to {@code /login?error}, which on a two-step page is
 * step one — so a single mistyped character costs the address as well, and the person retypes both.
 *
 * <p>The address is echoed back from what was just submitted rather than looked up, so this reveals
 * nothing about whether it has an account. The message the page shows is the same either way.
 *
 * <p>Redirects directly rather than extending {@code SimpleUrlAuthenticationFailureHandler} and
 * calling {@code setDefaultFailureUrl}: that setter mutates the handler, which is a singleton, so two
 * people failing a sign-in at the same moment could each be redirected with the other's address.
 */
@Component
public class LoginFailureHandler implements AuthenticationFailureHandler {

    private final RedirectStrategy redirects = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        String username = request.getParameter("username");
        String target = "/login?error";
        if (username != null && !username.isBlank()) {
            target += "&method=choose&email=" + UriUtils.encodeQueryParam(username, StandardCharsets.UTF_8);
        }
        redirects.sendRedirect(request, response, target);
    }
}
