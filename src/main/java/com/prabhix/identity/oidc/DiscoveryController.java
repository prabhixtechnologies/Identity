package com.prabhix.identity.oidc;

import com.prabhix.identity.config.IdentityProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * The OpenID Connect discovery document, at the path the specification fixes.
 *
 * <p>Its job here is narrow: let a product find the JWKS and confirm the issuer and algorithm from
 * one well-known URL, so a key rotation or a move to a different host is a change in this service
 * rather than a redeploy of every client. Spring Security's resource-server support reads exactly
 * this document given an issuer URI, which is what the platform will point at during the cutover.
 *
 * <p>It advertises only what actually exists. There is no authorisation endpoint and no
 * authorization_code flow — sign-in is the platform's existing password, OTP, magic-link and Google
 * flows, which are not OAuth grants. Listing endpoints that are not implemented would make a
 * conformant client fail in a way that looks like our bug, so {@code grant_types_supported} says
 * refresh_token and nothing more.
 */
@RestController
@RequiredArgsConstructor
public class DiscoveryController {

    private final IdentityProperties properties;

    @GetMapping("/.well-known/openid-configuration")
    public ResponseEntity<Map<String, Object>> configuration() {
        String issuer = properties.issuer();

        Map<String, Object> document = new LinkedHashMap<>();
        document.put("issuer", issuer);
        document.put("jwks_uri", issuer + "/.well-known/jwks.json");
        document.put("id_token_signing_alg_values_supported", List.of("RS256"));
        document.put("subject_types_supported", List.of("public"));
        document.put("grant_types_supported", List.of("refresh_token"));
        document.put("response_types_supported", List.of());
        // Exactly the claims TokenService puts in a token. Advertising one we do not issue — aud is
        // the tempting one — invites a client to require it and fail on every token we sign.
        document.put("claims_supported",
                List.of("iss", "sub", "exp", "iat", "jti", "email", "email_verified", "name",
                        "sid", "amr"));
        document.put("scopes_supported", List.of("openid", "email", "profile"));

        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(10, TimeUnit.MINUTES).cachePublic())
                .body(document);
    }
}
