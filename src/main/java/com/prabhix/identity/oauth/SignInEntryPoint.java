package com.prabhix.identity.oauth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

/**
 * Where an unauthenticated {@code /authorize} sends the browser: the sign-in page, or the signup one.
 *
 * <p>Both start the same way — Spring saves the authorization request in the session and redirects —
 * and that saved request is the whole point of coming through here. Whichever page finishes, the
 * success handler resumes it, so somebody who signs up from the admin console lands back in the admin
 * console rather than wherever the default happens to point.
 *
 * <p>Sending the browser straight to {@code /signup} instead would skip that: nothing would be saved,
 * and every new account would finish in the same product regardless of which one it came from.
 *
 * <p>{@code prompt=create} is from OpenID Connect's registration extension rather than invented here.
 * It travels as an ordinary authorization parameter, so a product that does not know about it is
 * unaffected, and a client that sends it is asking for exactly what it says.
 */
public class SignInEntryPoint extends LoginUrlAuthenticationEntryPoint {

    private static final String SIGNUP_URL = "/signup";

    public SignInEntryPoint(String loginUrl) {
        super(loginUrl);
    }

    @Override
    protected String determineUrlToUseForThisRequest(HttpServletRequest request,
                                                     HttpServletResponse response,
                                                     AuthenticationException exception) {
        return wantsToRegister(request)
                ? SIGNUP_URL
                : super.determineUrlToUseForThisRequest(request, response, exception);
    }

    /**
     * {@code prompt} is a space-delimited list, so this is a membership test and not an equality one.
     * A client may reasonably send {@code prompt=create login}, and matching the whole string would
     * quietly send that person to sign in instead — with no error anywhere to explain why the signup
     * button opened a login page.
     */
    private static boolean wantsToRegister(HttpServletRequest request) {
        String prompt = request.getParameter("prompt");
        if (prompt == null) {
            return false;
        }
        for (String value : prompt.split("\\s+")) {
            if ("create".equals(value)) {
                return true;
            }
        }
        return false;
    }
}
