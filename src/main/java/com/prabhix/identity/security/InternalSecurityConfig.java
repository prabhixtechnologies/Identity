package com.prabhix.identity.security;

import com.prabhix.identity.security.internal.InternalServiceAuthFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Dedicated chain for {@code /internal/**} so service authentication runs before any other matcher.
 */
@Configuration
public class InternalSecurityConfig {

    @Bean
    @Order(0)
    public SecurityFilterChain internalServiceChain(HttpSecurity http,
                                                    InternalServiceAuthFilter internalAuth) throws Exception {
        http
                .securityMatcher("/internal/**")
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(requests -> requests.anyRequest().permitAll())
                .addFilterBefore(internalAuth, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
