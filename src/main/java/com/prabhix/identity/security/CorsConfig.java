package com.prabhix.identity.security;

import com.prabhix.identity.config.IdentityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.ArrayList;
import java.util.List;

/**
 * Browser SPAs redeem authorization codes at {@code /oauth2/token} from their own origin.
 *
 * <p>Without CORS, that fetch fails in the browser as "Failed to fetch" even when Identity is
 * healthy — which is exactly what a local MobiStack callback looks like. Origins are derived from
 * the same first-party redirect URIs already registered for OAuth clients, so local ports and
 * production hostnames stay aligned without a second list to drift.
 */
@Configuration
public class CorsConfig {

    @Bean
    public CorsConfigurationSource corsConfigurationSource(IdentityProperties properties) {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(new ArrayList<>(FirstPartyHttpOrigins.from(properties)));
        config.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
