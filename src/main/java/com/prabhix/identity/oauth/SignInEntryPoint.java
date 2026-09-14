package com.prabhix.identity.oauth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.web.util.UriComponentsBuilder;

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
 *
 * <p>{@code prompt=none} is the other direction: the client is asking not to be shown a page at all.
 * That is how a product recovers a session from the cookie on this origin without flashing its own
 * welcome screen. The authorization-server chain requires an authenticated user, so without this
 * branch the browser would land on {@code /login} and the silent check would become an interactive
 * one. OpenID Connect requires {@code login_required} on the registered redirect URI instead. The
 * URI is matched exactly against the registered client — the same rule as the authorization
 * endpoint — so this cannot become an open redirect.
 */
public class SignInEntryPoint extends LoginUrlAuthenticationEntryPoint {

    private static final String SIGNUP_URL = "/signup";

    private final RegisteredClientRepository clients;

    public SignInEntryPoint(String loginUrl) {
        this(loginUrl, null);
    }

    public SignInEntryPoint(String loginUrl, RegisteredClientRepository clients) {
        super(loginUrl);
        this.clients = clients;
    }

    @Override
    protected String determineUrlToUseForThisRequest(HttpServletRequest request,
                                                     HttpServletResponse response,
                                                     AuthenticationException exception) {
        if (promptContains(request, "none")) {
            String silentFailure = silentFailureUrl(request);
            if (silentFailure != null) {
                return silentFailure;
            }
        }
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
        return promptContains(request, "create");
    }

    private static boolean promptContains(HttpServletRequest request, String expected) {
        String prompt = request.getParameter("prompt");
        if (prompt == null) {
            return false;
        }
        for (String value : prompt.split("\\s+")) {
            if (expected.equals(value)) {
                return true;
            }
        }
        return false;
    }

    private String silentFailureUrl(HttpServletRequest request) {
        String clientId = request.getParameter("client_id");
        String redirectUri = request.getParameter("redirect_uri");
        if (clients == null || clientId == null || redirectUri == null) {
            return null;
        }
        RegisteredClient client = clients.findByClientId(clientId);
        if (client == null || !client.getRedirectUris().contains(redirectUri)) {
            return null;
        }
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("error", "login_required")
                .queryParam("error_description", "End-User authentication is required");
        String state = request.getParameter("state");
        if (state != null && !state.isEmpty()) {
            builder.queryParam("state", state);
        }
        return builder.encode().build().toUriString();
    }
}
