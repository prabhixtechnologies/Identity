package com.prabhix.identity.jwks;

import com.prabhix.identity.config.IdentityProperties;
import com.prabhix.identity.config.TestProperties;
import com.prabhix.identity.oidc.DiscoveryController;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The two documents every product reads before it can verify a single request. Their paths and
 * member names are fixed by RFC 7517 and OpenID Connect Discovery, so they are asserted literally:
 * a client library builds the URL itself and will not tell us if we renamed something.
 */
class WellKnownEndpointsTest {

    private static final String ISSUER = TestProperties.ISSUER;

    private static IdentityProperties properties(String privateKey, List<String> retired) {
        return TestProperties.signing(privateKey, retired);
    }

    @Test
    @DisplayName("the JWKS publishes a public RSA key and never the private half")
    void jwksPublishesPublicKeyOnly() throws Exception {
        IdentityProperties properties = properties(TestKeys.privatePem(TestKeys.pair()), List.of());
        SigningKeyProvider keys = new SigningKeyProvider(properties, new MockEnvironment());
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new JwksController(keys)).build();

        mvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
                .andExpect(jsonPath("$.keys[0].use").value("sig"))
                .andExpect(jsonPath("$.keys[0].kid").value(keys.active().keyId()))
                .andExpect(jsonPath("$.keys[0].n").exists())
                .andExpect(jsonPath("$.keys[0].e").exists())
                // d is the private exponent. jjwt's RsaPublicJwk cannot hold it, and this asserts
                // that the serialisation does not somehow reach the private key anyway.
                .andExpect(jsonPath("$.keys[0].d").doesNotExist())
                .andExpect(jsonPath("$.keys[0].p").doesNotExist());
    }

    @Test
    @DisplayName("the JWKS lists a retired key too, so a rotation is not an outage")
    void jwksIncludesRetiredKey() throws Exception {
        IdentityProperties properties = properties(
                TestKeys.privatePem(TestKeys.pair()), List.of(TestKeys.publicPem(TestKeys.pair())));
        SigningKeyProvider keys = new SigningKeyProvider(properties, new MockEnvironment());
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new JwksController(keys)).build();

        mvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys.length()").value(2));
    }

    @Test
    @DisplayName("discovery points at the JWKS and advertises only what is implemented")
    void discoveryDocument() throws Exception {
        MockMvc mvc = MockMvcBuilders
                .standaloneSetup(new DiscoveryController(properties("", List.of())))
                .build();

        mvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value(ISSUER))
                .andExpect(jsonPath("$.jwks_uri").value(ISSUER + "/.well-known/jwks.json"))
                .andExpect(jsonPath("$.id_token_signing_alg_values_supported[0]").value("RS256"))
                // Sign-in is password, OTP, magic link and Google — none of them OAuth grants. A
                // conformant client offered authorization_code would fail in a way that looks like
                // our bug rather than a missing feature.
                .andExpect(jsonPath("$.grant_types_supported").value("refresh_token"))
                .andExpect(jsonPath("$.response_types_supported").isEmpty());
    }
}
