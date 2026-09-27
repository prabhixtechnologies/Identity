package com.prabhix.identity.oauth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Returns a failed password attempt to the step it was made on, with the address still filled in.
 *
 * <p>Spring Security's default sends everything to {@code /login?error}, which on a two-step page is
 * step one — so a single mistyped character costs the address as well, and the person retypes both.
 *
 * <p>The address is kept in {@link LoginChallengeState} (session), not the query string — echoing it
 * in {@code ?email=} would put PII in history and logs on every failed attempt.
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
        if (username != null && !username.isBlank()) {
            LoginChallengeState.setEmail(request, username);
        }
        redirects.sendRedirect(request, response, "/login?error=" + reason(exception) + "&method=choose");
    }

    /**
     * The one failure the page is allowed to describe.
     *
     * <p>{@link IdentityAuthenticationProvider} already collapses "no such account" and "wrong
     * password" into one {@code BadCredentialsException} so the form cannot be used to discover
     * which addresses have accounts. A lock is different: the account's existence is not the
     * secret, and the person hitting it is almost always its owner, who otherwise retypes a
     * password that is correct and keeps being told it is wrong.
     *
     * <p>The message itself lives in the template, not here — a redirect parameter is attacker
     * controlled, so the controller maps this token to fixed copy rather than rendering it.
     */
    private static String reason(AuthenticationException exception) {
        return exception instanceof LockedException ? "locked" : "credentials";
    }
}
