package com.prabhix.identity.oauth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

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
                                            LoginFailureHandler failureHandler) throws Exception {
        http
                .securityMatcher("/login", "/login/**", "/oauth2/consent", "/assets/**", "/logout")
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers("/login", "/login/**", "/assets/**").permitAll()
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
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?signedOut")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID"))
                // Form posts are cookie-authenticated, so this chain is exactly the CSRF surface the
                // API chain is not. Left enabled, with the token rendered into the form.
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));

        return http.build();
    }
}
