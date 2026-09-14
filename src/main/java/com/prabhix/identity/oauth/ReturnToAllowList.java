package com.prabhix.identity.oauth;

import com.prabhix.identity.config.IdentityProperties;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * The {@code return_to} query on {@code /account}, checked against registered client URLs.
 *
 * <p>Exact match, never a prefix. A prefix match on an open redirect is how an authorization code
 * ends up at an origin nobody registered. The same list is used here so a product can deep-link
 * {@code {issuer}/account?return_to=...} and the "Back to app" button can only go where that client
 * was already allowed to send a browser.
 */
@Component
public class ReturnToAllowList {

    private final JdbcTemplate jdbc;
    private final IdentityProperties properties;

    public ReturnToAllowList(JdbcTemplate jdbc, IdentityProperties properties) {
        this.jdbc = jdbc;
        this.properties = properties;
    }

    public Optional<String> validated(String returnTo) {
        if (returnTo == null || returnTo.isBlank()) {
            return Optional.empty();
        }
        String candidate = returnTo.trim();
        return allowed().contains(candidate) ? Optional.of(candidate) : Optional.empty();
    }

    private Set<String> allowed() {
        Set<String> urls = new LinkedHashSet<>();
        jdbc.query("select redirect_uris, post_logout_redirect_uris from oauth2_registered_client", rs -> {
            addAll(urls, rs.getString("redirect_uris"));
            addAll(urls, rs.getString("post_logout_redirect_uris"));
        });
        // Config as well as the table, so a first boot before the seeder has run still refuses
        // anything that is not a client we would have registered, rather than refusing everything.
        if (properties.clients() != null) {
            for (IdentityProperties.Client client : properties.clients()) {
                addAll(urls, client.redirectUris());
                addAll(urls, client.postLogoutRedirectUris());
            }
        }
        return urls;
    }

    private static void addAll(Set<String> urls, String csv) {
        if (csv == null || csv.isBlank()) {
            return;
        }
        Arrays.stream(csv.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .forEach(urls::add);
    }

    private static void addAll(Set<String> urls, List<String> values) {
        if (values == null) {
            return;
        }
        values.stream()
                .filter(s -> s != null && !s.isBlank())
                .map(String::trim)
                .forEach(urls::add);
    }
}
