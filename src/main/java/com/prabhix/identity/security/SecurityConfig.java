package com.prabhix.identity.security;

import com.prabhix.identity.common.ApiError;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.config.IdentityProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final IdentityAuthenticationFilter authenticationFilter;
    private final ObjectMapper objectMapper;
    private final IdentityProperties properties;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // No CSRF token. Nothing here is authenticated by a cookie alone: the session cookie
                // is only ever exchanged at one endpoint, and that endpoint is idempotent and hands
                // back a short-lived token rather than performing an action.
                .csrf(csrf -> csrf.disable())
                .cors(Customizer.withDefaults())
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(requests -> requests
                        // Public because they are how you become authenticated in the first place.
                        .requestMatchers(
                                "/api/v1/auth/register",
                                "/api/v1/auth/login",
                                "/api/v1/auth/refresh",
                                "/api/v1/auth/session/token",
                                "/api/v1/auth/magic-link/**",
                                "/api/v1/auth/otp/**",
                                "/api/v1/auth/sso/**",
                                "/api/v1/auth/password/forgot",
                                "/api/v1/auth/password/reset",
                                "/api/v1/auth/email/verify/confirm").permitAll()
                        // The whole point of publishing keys is that anyone can fetch them.
                        .requestMatchers("/.well-known/**").permitAll()
                        .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                        .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                        // Guarded by a shared service token inside the controller, not by a bearer
                        // token, because the caller is a product rather than a person.
                        .requestMatchers("/internal/**").permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling(handling -> handling.authenticationEntryPoint(entryPoint()))
                .addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Produces the same {@link ApiError} body as every other failure, so a client parsing a 401 from
     * this service does not need a special case for the ones Spring Security generates itself.
     */
    private AuthenticationEntryPoint entryPoint() {
        return (request, response, exception) -> {
            response.setStatus(ErrorCode.UNAUTHENTICATED.status().value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            objectMapper.writeValue(response.getOutputStream(), ApiError.of(
                    ErrorCode.UNAUTHENTICATED,
                    "Sign in to continue",
                    null,
                    request.getRequestURI()));
        };
    }

    /**
     * BCrypt at the platform's strength.
     *
     * <p>Imported hashes were written at other strengths — MobiStack's at 12, platform's at 10 — and
     * verify regardless, because bcrypt stores its cost factor inside the hash. This setting only
     * decides the cost of hashes written from now on, which is why an import needs nobody to reset a
     * password.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(properties.password().bcryptStrength());
    }
}
