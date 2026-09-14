package com.prabhix.identity.client;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

/**
 * Wires the identity client from {@code prabhix.identity.*}.
 *
 * <p>Everything is {@code @ConditionalOnMissingBean}, so a product that needs a different HTTP client
 * or a test that wants a stub key source declares its own bean and this steps aside. The mirror only
 * appears when the product has said where to write, by providing a {@link UserMirrorStore}.
 */
@AutoConfiguration
@EnableConfigurationProperties(IdentityClientProperties.class)
public class IdentityClientAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(name = "identityRestClient")
    RestClient identityRestClient(IdentityClientProperties config,
                                  ObjectProvider<RestClient.Builder> builders) {
        RestClient.Builder builder = builders.getIfAvailable(RestClient::builder);
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(config.internalTimeout());
        factory.setReadTimeout(config.internalTimeout());
        return builder.clone().requestFactory(factory).build();
    }

    @Bean
    @ConditionalOnMissingBean
    IdentityKeySource identityKeySource(IdentityClientProperties config, RestClient identityRestClient) {
        return new IdentityKeySource(config, identityRestClient);
    }

    @Bean
    @ConditionalOnMissingBean
    IdentityTokenVerifier identityTokenVerifier(IdentityClientProperties config, IdentityKeySource keys) {
        return new IdentityTokenVerifier(config, keys);
    }

    @Bean
    @ConditionalOnMissingBean
    IdentityInternalClient identityInternalClient(IdentityClientProperties config, RestClient identityRestClient) {
        return new IdentityInternalClient(config, identityRestClient);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(UserMirrorStore.class)
    IdentityUserMirror identityUserMirror(IdentityInternalClient client, UserMirrorStore store) {
        return new IdentityUserMirror(client, store);
    }

    @Bean
    @ConditionalOnMissingBean
    ServiceTokenGuard serviceTokenGuard(IdentityClientProperties config) {
        return new ServiceTokenGuard(config);
    }
}
