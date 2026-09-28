package com.prabhix.identity.oauth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Which product's colours the hosted pages should wear, taken from the authorization request that
 * was waiting when the page opened.
 *
 * <p>Arriving at Mailroom's sign-in and being shown Prabhix Technologies cyan reads as a redirect to
 * somewhere else. Wearing the product's own accent pair is both the honest answer to "where am I"
 * and a small anti-phishing signal: a copy of this page cannot know which client sent you.
 *
 * <p>The mapping is an allowlist to a closed set of literals and the {@code client_id} itself is
 * never returned. It arrives from a query string, so echoing it into a {@code data-brand} attribute
 * would put attacker-chosen text into the document; an unrecognised client falls back to the house
 * brand instead. {@link #HOUSE} is also the answer when there is no pending authorization request at
 * all, which is what someone visiting {@code /login} directly sees.
 */
@Component
public class SignInBrand {

    /** The parent identity, used when nothing more specific is known. */
    public static final String HOUSE = "technologies";

    /**
     * Every registered client, mapped to the theme declared in tokens.json.
     *
     * <p>Web and Android clients are separate registrations because their redirect URIs are
     * different shapes, but they are the same product to the person signing in. {@code
     * prabhix-console} is OneOps: the client id predates the product being named, and renaming a
     * registered client would break every deployment holding the old id.
     */
    private static final Map<String, String> BRANDS = Map.ofEntries(
            Map.entry("prabhix-console", "oneops"),
            Map.entry("prabhix-oneops-android", "oneops"),
            Map.entry("prabhix-admin", "admin"),
            Map.entry("prabhix-admin-android", "admin"),
            Map.entry("prabhix-mailroom", "mailroom"),
            Map.entry("prabhix-mailroom-android", "mailroom"),
            Map.entry("prabhix-mobistack", "mobistack"),
            Map.entry("prabhix-mobistack-android", "mobistack"));

    private final HttpSessionRequestCache savedRequests = new HttpSessionRequestCache();

    /**
     * Reads the pending request without consuming it.
     *
     * <p>Non-destructive on purpose: the same saved request still has to survive to redirect the
     * person onward once they are signed in.
     */
    public String forRequest(HttpServletRequest request, HttpServletResponse response) {
        SavedRequest saved = savedRequests.getRequest(request, response);
        if (saved == null) {
            return HOUSE;
        }
        String[] clientIds = saved.getParameterValues("client_id");
        if (clientIds == null) {
            return HOUSE;
        }
        for (String clientId : clientIds) {
            String brand = BRANDS.get(clientId);
            if (brand != null) {
                return brand;
            }
        }
        return HOUSE;
    }
}
