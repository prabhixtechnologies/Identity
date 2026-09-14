package com.prabhix.identity.oauth;

import com.prabhix.identity.config.IdentityProperties;
import com.prabhix.identity.event.AuthEventRecorder;
import com.prabhix.identity.event.AuthEventType;
import com.prabhix.identity.security.FirstPartyHttpOrigins;
import com.prabhix.identity.session.SessionCookieService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.UUID;

import static com.prabhix.identity.event.AuthEventRecorder.details;

/**
 * The one login page every Prabhix property redirects to.
 *
 * <p>This is what makes single sign-on work rather than merely be claimed. Because the page is served
 * from this origin, the session cookie is set here — so the second product's {@code /authorize} finds
 * an existing session and returns a code without asking for a password again. A login form hosted
 * inside each product cannot do that: each would set a cookie on its own origin, and the browser would
 * have as many sessions as there are products.
 *
 * <p>Sessions are enabled on this chain and only this chain. The authorization request has to be held
 * somewhere while the person types their password, and the API chain in {@code SecurityConfig} stays
 * stateless.
 */
@Configuration
public class LoginUiConfig {

    @Bean
    @Order(2)
    public SecurityFilterChain loginUiChain(HttpSecurity http,
                                            LoginFailureHandler failureHandler,
                                            IdentityProperties properties,
                                            SessionCookieService sessionCookies,
                                            AuthEventRecorder events) throws Exception {
        http
                // /signup and /account belong on this chain and not the API one: they are documents
                // with a form, so they need a session to hold the pending authorization request (or
                // the return_to) and a CSRF token in the form, and they need the CSP below or the
                // gateway's floor stops them submitting at all.
                .securityMatcher("/login", "/login/**", "/signup", "/oauth2/consent", "/assets/**",
                        "/logout", "/account", "/account/**")
                .cors(Customizer.withDefaults())
                // Default XOR handler + deferred token is a known 403 on the password POST in
                // Chrome Custom Tabs (AppAuth). Plain attribute handler + reading the token in
                // the form is enough for a same-origin cookie session.
                .csrf(csrf -> csrf.csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()))
                .exceptionHandling(ex -> ex.accessDeniedHandler((request, response, denied) ->
                        response.sendRedirect("/login?error&method=choose")))
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers("/login", "/login/**", "/signup", "/assets/**", "/logout").permitAll()
                        // Token in the query string is the proof, same as /login/link.
                        .requestMatchers("/account/email/confirm").permitAll()
                        .anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/login")
                        // /account is a legitimate saved request: a product deep-link while signed
                        // out should resume here after the password, not dump into the console.
                        .permitAll()
                        // The page asks for the address and the password on separate steps, so the
                        // default /login?error would discard the address along with the attempt.
                        .failureHandler(failureHandler))
                .logout(logout -> logout
                        // GET as well as POST: product SPAs navigate here when they have no
                        // id_token_hint for /connect/logout (SSO via another app's cookie, or a lost
                        // sessionStorage). POST-only left those browsers on a 400 and still signed in.
                        .logoutRequestMatcher(logoutGetOrPost())
                        .logoutSuccessUrl("/login?signedOut")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        // Servlet deleteCookies does not honor Domain= on pbx_session, so the
                        // shared parent-domain cookie would survive a hosted sign-out.
                        .addLogoutHandler((request, response, authentication) ->
                                sessionCookies.clear(response))
                        // Before Spring's own handler clears the context, while there is still an
                        // authentication to name. The principal is the user id, per HostedSignIn.
                        .addLogoutHandler((request, response, authentication) -> {
                            if (authentication != null) {
                                hostedUserId(authentication.getName()).ifPresent(userId ->
                                        events.success(AuthEventType.LOGOUT, userId, null,
                                                details("surface", "hosted")));
                            }
                        }))
                // Form posts are cookie-authenticated, so this chain is exactly the CSRF surface the
                // API chain is not. Left enabled, with the token rendered into the form.
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                // Sent by this service because it is this service that serves the document.
                //
                // The gateway applies a floor of `default-src 'none'; form-action 'none'` to every
                // response on this hostname that does not carry a policy of its own, which is right
                // for an API and ruinous for a login page: unstyled, scriptless, and — because of
                // form-action — unable to submit the form at all. It is set only when absent, so
                // sending one here is what replaces it.
                .headers(headers -> headers
                        .contentSecurityPolicy(csp ->
                                csp.policyDirectives(FirstPartyHttpOrigins.loginCsp(properties))));

        return http.build();
    }

    private static java.util.Optional<UUID> hostedUserId(String principalName) {
        try {
            return java.util.Optional.of(UUID.fromString(principalName));
        } catch (IllegalArgumentException | NullPointerException ex) {
            return java.util.Optional.empty();
        }
    }

    /** Matches browser navigations (GET) and form posts (POST) to the hosted sign-out URL. */
    private static RequestMatcher logoutGetOrPost() {
        return request -> {
            String path = request.getRequestURI();
            if (path == null) {
                return false;
            }
            // Context path is empty in our images; still tolerate a trailing slash from a proxy.
            if (!"/logout".equals(path) && !path.endsWith("/logout")) {
                return false;
            }
            String method = request.getMethod();
            return "GET".equalsIgnoreCase(method) || "POST".equalsIgnoreCase(method);
        };
    }

}
