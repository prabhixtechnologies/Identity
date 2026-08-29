package com.prabhix.identity.oauth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.prabhix.identity.config.IdentityProperties;
import com.prabhix.identity.jwks.SigningKeyProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 * The OAuth2 and OpenID Connect surface: what makes this an identity provider rather than a login
 * endpoint.
 *
 * <p>The distinction matters for the thousand sites this is meant to serve. A login endpoint takes a
 * password over an API, which means every site handling one — the exact thing centralising identity is
 * supposed to prevent. An authorization server redirects instead: credentials are only ever typed on
 * this origin, and a site receives a code it exchanges for tokens.
 *
 * <p>Three filter chains, in order. The authorization server's own endpoints come first because its
 * matcher is specific and it has to win. The login and consent pages come second, and need a session:
 * the authorization request is held there while the person signs in. The stateless API chain in
 * {@code SecurityConfig} comes last, since it matches everything left over.
 */
@Configuration
public class AuthorizationServerConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                // Turns on the OIDC half: the id_token, /userinfo, and RP-initiated logout. Dynamic
                // client registration stays off — a client that can register itself can choose its own
                // redirect URI, which is the whole attack.
                .oidc(Customizer.withDefaults());

        http.exceptionHandling(handling -> handling
                // Only for a browser. An API client that lands here should get a 401 rather than a
                // redirect to a page it cannot render.
                .defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        new MediaTypeRequestMatcher(org.springframework.http.MediaType.TEXT_HTML)));

        return http.build();
    }

    /**
     * Where the keys and the discovery document live.
     *
     * <p>The JWKS is moved onto {@code /.well-known/jwks.json}, which is the path products are already
     * configured with and the one the previous hand-written controller served. Leaving it at Spring's
     * default {@code /oauth2/jwks} would mean every product had to be reconfigured to keep verifying,
     * for no gain.
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings(IdentityProperties properties) {
        return AuthorizationServerSettings.builder()
                .issuer(properties.issuer())
                .jwkSetEndpoint("/.well-known/jwks.json")
                .build();
    }

    /**
     * Bridges the authorization server to the key this service already signs with.
     *
     * <p>One key provider, not two. Spring Authorization Server would happily generate its own key
     * pair, and then tokens minted through the authorization code flow would be signed by a key absent
     * from the published JWKS — verifying nowhere.
     *
     * <p>The key id is an RFC 7638 thumbprint in both libraries, so it comes out identical and a token
     * issued before this change still names a key that is still published.
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource(SigningKeyProvider keys) {
        try {
            List<com.nimbusds.jose.jwk.JWK> jwks = new ArrayList<>();

            jwks.add(new RSAKey.Builder(keys.active().publicKey())
                    .privateKey(keys.active().privateKey())
                    .keyIDFromThumbprint()
                    .build());

            // Retired keys are verify-only: no private half, so nothing can be signed with them, and
            // a token issued before the last rotation still verifies until it expires.
            for (var retired : keys.published()) {
                if (retired.getId().equals(keys.active().keyId())) {
                    continue;
                }
                jwks.add(new RSAKey.Builder((RSAPublicKey) retired.toKey())
                        .keyIDFromThumbprint()
                        .build());
            }

            JWKSet set = new JWKSet(jwks);
            return (selector, context) -> selector.select(set);
        } catch (JOSEException ex) {
            // Only thrown if the thumbprint cannot be computed, which for a key this service has
            // already validated means the JVM is missing SHA-256. Nothing can be signed either way.
            throw new IllegalStateException("Could not derive a key id for the signing key", ex);
        }
    }

    /** Verifies the id_tokens this server issues, which RP-initiated logout has to read. */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * Authorizations in the database rather than in memory.
     *
     * <p>In memory, a restart loses every in-flight authorization code and every refresh token with
     * it, and a second replica cannot complete a flow the first one started — the code is redeemed
     * against whichever instance the load balancer happens to pick.
     */
    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbc,
                                                          RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationService(jdbc, clients);
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(
            JdbcTemplate jdbc, RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationConsentService(jdbc, clients);
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbc) {
        return new JdbcRegisteredClientRepository(jdbc);
    }
}
