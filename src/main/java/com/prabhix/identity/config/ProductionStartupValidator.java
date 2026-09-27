package com.prabhix.identity.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.Arrays;
import java.util.Locale;
import java.util.Set;

/**
 * Refuses to stay up in production with known-weak identity configuration.
 */
@Slf4j
@Component
public class ProductionStartupValidator {

    private static final Set<String> LOCAL_PROFILES = Set.of("dev", "test", "local");
    private static final Set<String> WEAK_DB_PASSWORDS = Set.of("identity", "postgres", "password", "changeme");

    private final Environment environment;
    private final IdentityProperties properties;

    public ProductionStartupValidator(Environment environment, IdentityProperties properties) {
        this.environment = environment;
        this.properties = properties;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void validate() {
        if (isLocalProfile()) {
            return;
        }
        log.info("Validating production identity configuration");
        requireHttpsIssuer(properties.issuer());
        requireSigningKeyConfigured();
        requireServiceTokenConfigured();
        requireDatabaseCredentials();
    }

    private boolean isLocalProfile() {
        String[] active = environment.getActiveProfiles();
        if (active.length == 0) {
            return true;
        }
        return Arrays.stream(active).anyMatch(profile -> LOCAL_PROFILES.contains(profile.toLowerCase(Locale.ROOT)));
    }

    private void requireHttpsIssuer(String issuer) {
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalStateException("IDENTITY_ISSUER must be set in production");
        }
        URI uri = URI.create(issuer);
        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            throw new IllegalStateException("IDENTITY_ISSUER must use https in production");
        }
        String host = uri.getHost();
        if (host == null || host.equals("localhost") || host.endsWith(".local")) {
            throw new IllegalStateException("IDENTITY_ISSUER must not point at localhost in production");
        }
    }

    private void requireSigningKeyConfigured() {
        String key = properties.signing().privateKey();
        if (key == null || key.isBlank()) {
            throw new IllegalStateException("IDENTITY_SIGNING_KEY must be configured in production");
        }
    }

    private void requireServiceTokenConfigured() {
        String token = properties.serviceToken();
        if (token == null || token.isBlank()) {
            throw new IllegalStateException("Identity service token must be configured in production");
        }
        if ("test-service-token".equals(token)) {
            throw new IllegalStateException("Identity service token must not use the development default");
        }
    }

    private void requireDatabaseCredentials() {
        String user = environment.getProperty("spring.datasource.username", "");
        String password = environment.getProperty("spring.datasource.password", "");
        if (user.isBlank() || "identity".equalsIgnoreCase(user)) {
            throw new IllegalStateException("Identity database user must not use the development default");
        }
        if (password.isBlank() || WEAK_DB_PASSWORDS.contains(password.toLowerCase(Locale.ROOT))) {
            throw new IllegalStateException("Identity database password must not use a known default");
        }
    }
}
