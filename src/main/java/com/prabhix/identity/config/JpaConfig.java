package com.prabhix.identity.config;

import com.prabhix.identity.security.AuthenticatedCaller;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;
import java.util.UUID;

@Configuration
@EnableJpaAuditing(auditorAwareRef = "auditorAware")
public class JpaConfig {

    /**
     * Fills {@code created_by} and {@code updated_by}.
     *
     * <p>Empty for every unauthenticated flow, which is most of this service: nobody is signed in
     * while they are registering or resetting a password, and inventing an auditor for those would put
     * a misleading id on the row. The interesting provenance for those rows is the challenge's
     * {@code ip_address}, which is recorded explicitly.
     */
    @Bean
    public AuditorAware<UUID> auditorAware() {
        return () -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication == null
                    || !(authentication.getPrincipal() instanceof AuthenticatedCaller caller)) {
                return Optional.empty();
            }
            return Optional.of(caller.userId());
        };
    }
}
