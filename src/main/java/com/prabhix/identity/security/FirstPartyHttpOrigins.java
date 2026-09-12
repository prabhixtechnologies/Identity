package com.prabhix.identity.security;

import com.prabhix.identity.config.IdentityProperties;

import java.net.URI;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Browser origins of first-party SPAs, derived from OAuth redirect URIs.
 *
 * <p>Used for CORS (token exchange) and for {@code form-action} (Chrome requires every redirect
 * after a login POST — including the product callback — to be listed, or it reports a misleading
 * block on the login URL itself).
 */
public final class FirstPartyHttpOrigins {

    private FirstPartyHttpOrigins() {
    }

    public static List<String> from(IdentityProperties properties) {
        Set<String> origins = new LinkedHashSet<>();
        add(origins, properties.urls().console());
        add(origins, properties.urls().admin());
        for (IdentityProperties.Client client : properties.clients()) {
            for (String uri : client.redirectUris()) {
                add(origins, uri);
            }
            for (String uri : client.postLogoutRedirectUris()) {
                add(origins, uri);
            }
        }
        return List.copyOf(origins);
    }

    private static void add(Set<String> origins, String uri) {
        if (uri == null || uri.isBlank()) {
            return;
        }
        try {
            URI parsed = URI.create(uri.trim());
            String scheme = parsed.getScheme();
            if (scheme == null || (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https"))) {
                return;
            }
            String host = parsed.getHost();
            if (host == null) {
                return;
            }
            int port = parsed.getPort();
            String origin = port > 0
                    ? scheme.toLowerCase() + "://" + host + ":" + port
                    : scheme.toLowerCase() + "://" + host;
            origins.add(origin);
        } catch (IllegalArgumentException ignored) {
            // Custom-scheme mobile redirects are not browser origins.
        }
    }
}
