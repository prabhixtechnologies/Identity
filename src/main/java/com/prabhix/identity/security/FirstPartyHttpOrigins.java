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
        addHttpOrigin(origins, properties.urls().console());
        addHttpOrigin(origins, properties.urls().admin());
        for (IdentityProperties.Client client : properties.clients()) {
            for (String uri : client.redirectUris()) {
                addHttpOrigin(origins, uri);
            }
            for (String uri : client.postLogoutRedirectUris()) {
                addHttpOrigin(origins, uri);
            }
        }
        return List.copyOf(origins);
    }

    /**
     * {@code form-action} sources for hosted login / authorize redirects.
     *
     * <p>Chrome applies {@code form-action} to the whole redirect chain after a password POST.
     * Identity → {@code /oauth2/authorize} → the product callback. HTTP SPA callbacks are origins;
     * Android AppAuth callbacks are custom schemes ({@code mobistack:}, {@code com.prabhix.admin:}).
     * Listing only {@code 'self'} (or HTTP origins) makes Chrome block that last hop and surface it
     * as a failure on {@code /login}.
     */
    public static List<String> formActionSources(IdentityProperties properties) {
        Set<String> sources = new LinkedHashSet<>();
        sources.add("'self'");
        sources.addAll(from(properties));
        if (properties.clients() != null) {
            for (IdentityProperties.Client client : properties.clients()) {
                addCustomSchemes(sources, client.redirectUris());
                addCustomSchemes(sources, client.postLogoutRedirectUris());
            }
        }
        return List.copyOf(sources);
    }

    /**
     * Content-Security-Policy for documents and 302s on the login / authorize chains.
     *
     * <p>Caddy stamps {@code form-action 'none'} on this hostname when a response has no policy of
     * its own. Authorize 302s must send this, or Chrome blocks the AppAuth custom-scheme return.
     */
    public static String loginCsp(IdentityProperties properties) {
        return String.join("; ",
                "default-src 'none'",
                "style-src 'self'",
                "script-src 'self' https://accounts.google.com",
                "frame-src https://accounts.google.com",
                "connect-src 'self' https://accounts.google.com",
                "img-src 'self' data:",
                "form-action " + String.join(" ", formActionSources(properties)),
                "base-uri 'none'",
                "frame-ancestors 'none'");
    }

    private static void addHttpOrigin(Set<String> origins, String uri) {
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

    private static void addCustomSchemes(Set<String> sources, List<String> uris) {
        if (uris == null) {
            return;
        }
        for (String uri : uris) {
            if (uri == null || uri.isBlank()) {
                continue;
            }
            try {
                String scheme = URI.create(uri.trim()).getScheme();
                if (scheme != null
                        && !scheme.equalsIgnoreCase("http")
                        && !scheme.equalsIgnoreCase("https")) {
                    sources.add(scheme + ":");
                }
            } catch (IllegalArgumentException ignored) {
                // Skip unparseable redirect URIs rather than abort CSP construction.
            }
        }
    }
}
