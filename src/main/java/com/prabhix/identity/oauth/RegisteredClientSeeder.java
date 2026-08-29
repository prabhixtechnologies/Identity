package com.prabhix.identity.oauth;

import com.prabhix.identity.config.IdentityProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.ApplicationArguments;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import java.util.UUID;

/**
 * Registers the first-party clients described in configuration.
 *
 * <p>Idempotent, and safe to run on every boot: an existing {@code client_id} is updated in place
 * rather than duplicated, so changing a redirect URI is a config change and a restart rather than a
 * migration.
 *
 * <p>Only ever touches clients named in configuration. A client registered through the admin console —
 * which is where third parties will be added — is never seen here and so cannot be silently rewritten
 * or removed by a deploy.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RegisteredClientSeeder implements ApplicationRunner {

    private final IdentityProperties properties;
    private final RegisteredClientRepository clients;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(ApplicationArguments args) {
        if (properties.clients() == null || properties.clients().isEmpty()) {
            log.warn("No OAuth clients configured. Nothing can complete an authorization code flow "
                    + "until at least one is registered.");
            return;
        }

        for (IdentityProperties.Client configured : properties.clients()) {
            if (configured.redirectUris() == null || configured.redirectUris().isEmpty()) {
                // Refused rather than registered without one. A client with no redirect URI fails at
                // /authorize with an error the developer cannot act on, hours after the deploy.
                throw new IllegalStateException(
                        "OAuth client " + configured.clientId() + " has no redirect URI");
            }
            clients.save(toRegisteredClient(configured));
            log.info("Registered OAuth client {} ({} redirect URI(s), {})",
                    configured.clientId(),
                    configured.redirectUris().size(),
                    configured.isPublicClient() ? "public, PKCE required" : "confidential");
        }
    }

    private RegisteredClient toRegisteredClient(IdentityProperties.Client configured) {
        // Reuses the existing row's id where there is one, because that is the foreign key
        // oauth2_authorization points at. A fresh id would orphan every live session for this client.
        RegisteredClient existing = clients.findByClientId(configured.clientId());
        String id = existing != null ? existing.getId() : UUID.randomUUID().toString();

        RegisteredClient.Builder builder = RegisteredClient.withId(id)
                .clientId(configured.clientId())
                .clientName(configured.name())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .clientSettings(ClientSettings.builder()
                        // Mandatory, not merely supported. A public client without PKCE is one
                        // intercepted redirect away from an attacker redeeming the code, and making it
                        // optional means a client can simply decline the protection.
                        .requireProofKey(true)
                        .requireAuthorizationConsent(!configured.firstParty())
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .accessTokenTimeToLive(properties.token().accessTokenTtl())
                        .refreshTokenTimeToLive(properties.token().refreshTokenTtl())
                        // A used refresh token is replaced, so a stolen one is detectable: the thief
                        // and the owner cannot both keep refreshing.
                        .reuseRefreshTokens(false)
                        .build());

        if (configured.isPublicClient()) {
            builder.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
        } else {
            builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    // Hashed, like a password. A readable client secret in the database is a readable
                    // client secret in every backup of it.
                    .clientSecret(passwordEncoder.encode(configured.secret()));
        }

        configured.redirectUris().forEach(builder::redirectUri);
        if (configured.postLogoutRedirectUris() != null) {
            configured.postLogoutRedirectUris().forEach(builder::postLogoutRedirectUri);
        }

        builder.scope(OidcScopes.OPENID);
        configured.scopes().forEach(builder::scope);

        return builder.build();
    }
}
