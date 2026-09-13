package com.prabhix.identity.oauth;

import com.prabhix.identity.config.IdentityProperties;
import com.prabhix.identity.security.FirstPartyHttpOrigins;
import com.prabhix.identity.session.SessionCookieService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.ArrayList;
import java.util.List;

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
                                            SessionCookieService sessionCookies) throws Exception {
        http
                // /signup belongs on this chain and not the API one: it is a document with a form, so
                // it needs a session to hold the pending authorization request and a CSRF token in the
                // form, and it needs the CSP below or the gateway's floor stops it submitting at all.
                .securityMatcher("/login", "/login/**", "/signup", "/oauth2/consent", "/assets/**",
                        "/logout")
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers("/login", "/login/**", "/signup", "/assets/**", "/logout").permitAll()
                        .anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/login")
                        // Nothing sensible to do on success beyond returning to whatever asked for
                        // authentication, which is always an /authorize request in practice.
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
                                sessionCookies.clear(response)))
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
                        .contentSecurityPolicy(csp -> csp.policyDirectives(loginCsp(properties))));

        return http.build();
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

    /**
     * Chrome applies {@code form-action} to the whole redirect chain after a form POST. A successful
     * sign-in goes Identity → {@code /oauth2/authorize} → the product callback. Listing only
     * {@code 'self'} makes Chrome block that last hop and misreport it as a block on {@code /login}.
     */
    private static String loginCsp(IdentityProperties properties) {
        List<String> formAction = new ArrayList<>();
        formAction.add("'self'");
        formAction.addAll(FirstPartyHttpOrigins.from(properties));

        return String.join("; ",
                "default-src 'none'",
                "style-src 'self'",
                // accounts.google.com for the sign-in button, which is absent from
                // the page unless a client id is configured. Naming it here costs
                // nothing when it is not.
                "script-src 'self' https://accounts.google.com",
                "frame-src https://accounts.google.com",
                // 'self' for passkey ceremony fetch(); Google for GIS token exchange.
                "connect-src 'self' https://accounts.google.com",
                "img-src 'self' data:",
                "form-action " + String.join(" ", formAction),
                "base-uri 'none'",
                "frame-ancestors 'none'");
    }
}
