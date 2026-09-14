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
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

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
 *
 * <p>As of Spring Security 7 the authorization server is part of Spring Security itself rather than a
 * separate project, so the configurer and the defaults now come from
 * {@code org.springframework.security.config.annotation.web} and not from a
 * {@code ...oauth2.server.authorization.config} package of their own. The classes kept their names,
 * so this reads the same as before; only the imports moved.
 */
@Configuration
public class AuthorizationServerConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerChain(HttpSecurity http,
                                                        RegisteredClientRepository clients,
                                                        OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator)
            throws Exception {
        // Spring Security 7 removed the static applyDefaultSecurity, so what it did is written out
        // here. It was three things, and all three still matter:
        //
        //   1. scope this chain to the authorization server's own endpoints, so it does not swallow
        //      requests belonging to the login chain or the API chain,
        //   2. require an authenticated user on them,
        //   3. exempt them from CSRF, because they are called by clients with a token or a client
        //      secret rather than by a browser carrying a session cookie.
        //
        // Dropping the third silently breaks the token endpoint for every client, so the matcher is
        // held in a local and used for both the matcher and the exemption rather than being built
        // twice — two matchers that are meant to be identical are two things that can drift.
        OAuth2AuthorizationServerConfigurer authorizationServer = new OAuth2AuthorizationServerConfigurer();
        RequestMatcher endpoints = authorizationServer.getEndpointsMatcher();

        http
                .securityMatcher(endpoints)
                .with(authorizationServer, server -> server
                        // Turns on the OIDC half: the id_token, /userinfo, and RP-initiated logout.
                        // Dynamic client registration stays off — a client that can register itself
                        // can choose its own redirect URI, which is the whole attack.
                        .oidc(Customizer.withDefaults())
                        .tokenGenerator(tokenGenerator)
                        // Append, do not replace: confidential-client converters must still run first
                        // when a client_secret is present. Ours only matches refresh_token + client_id.
                        .clientAuthentication(clientAuth -> {
                            clientAuth.authenticationConverters(converters ->
                                    converters.add(new PublicClientRefreshTokenAuthenticationConverter()));
                            clientAuth.authenticationProviders(providers ->
                                    providers.add(new PublicClientRefreshTokenAuthenticationProvider(clients)));
                        }))
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                // Browser SPAs POST here for the code exchange; without CORS the fetch fails before
                // PKCE even runs. Origins come from CorsConfigurationSource (first-party redirect URIs).
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpoints));

        http.exceptionHandling(handling -> handling
                // Only for a browser. An API client that lands here should get a 401 rather than a
                // redirect to a page it cannot render.
                .defaultAuthenticationEntryPointFor(
                        new SignInEntryPoint("/login", clients),
                        new MediaTypeRequestMatcher(org.springframework.http.MediaType.TEXT_HTML)));

        return http.build();
    }

    /**
     * Access / ID tokens via JWT, plus refresh tokens for first-party public (mobile) clients.
     *
     * <p>Replacing Spring's default refresh generator is required: it refuses to mint a refresh token
     * when the client authenticated with {@code none}, which is every Android AppAuth client we ship.
     */
    @Bean
    public OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator(
            JWKSource<SecurityContext> jwkSource,
            OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
        JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
        jwtGenerator.setJwtCustomizer(jwtCustomizer);
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        return new DelegatingOAuth2TokenGenerator(
                jwtGenerator, accessTokenGenerator, new PublicClientRefreshTokenGenerator());
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
