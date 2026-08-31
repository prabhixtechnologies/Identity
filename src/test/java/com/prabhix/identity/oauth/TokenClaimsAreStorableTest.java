package com.prabhix.identity.oauth;

import org.junit.jupiter.api.Test;
import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.security.oauth2.server.authorization.jackson.OAuth2AuthorizationServerJacksonModule;
import tools.jackson.databind.JacksonModule;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.type.TypeFactory;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Every claim this service adds has to survive a round trip through the authorization store.
 *
 * <p>An authorization's token claims are written to {@code oauth2_authorization.token_metadata} as
 * JSON carrying the concrete type of each value, and read back through a {@code
 * PolymorphicTypeValidator} that permits a fixed list of classes. A value outside that list
 * serializes without complaint and then cannot be read, so nothing fails at sign-in: the row is
 * written when the token is issued and only breaks whatever next reads that authorization back.
 *
 * <p>Which is how one claim took out four unrelated things at once. {@code List.of("pwd")} is an
 * {@code ImmutableCollections$List12} and is not on the list, so RP-initiated logout, introspection,
 * revocation and the refresh-token grant all answered {@code invalid_request} — reported as "OpenID
 * Connect 1.0 RP-Initiated Logout Error", which reads like a logout problem and is not one. Sign-out
 * appeared simply not to work.
 *
 * <p>So the test is the round trip rather than the type: it fails for any claim of any shape that
 * cannot be read back, including ones nobody has thought of yet.
 */
class TokenClaimsAreStorableTest {

    /** Configured exactly as {@code JdbcOAuth2AuthorizationService} configures its own. */
    private final JsonMapper mapper = jsonMapper();

    private static JsonMapper jsonMapper() {
        ClassLoader classLoader = TokenClaimsAreStorableTest.class.getClassLoader();
        List<JacksonModule> modules = new ArrayList<>(SecurityJacksonModules.getModules(classLoader));
        modules.add(new OAuth2AuthorizationServerJacksonModule());
        return JsonMapper.builder().addModules(modules).build();
    }

    @Test
    void theAmrClaimSurvivesTheRoundTrip() {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("amr", storableAmr());

        Map<String, Object> read = roundTrip(claims);

        assertEquals(List.of("pwd"), read.get("amr"));
    }

    /**
     * The bug itself, so the round trip above is known to be capable of failing.
     *
     * <p>A test that only asserts the good case passes just as well against a validator that permits
     * everything, which would tell us nothing about the constraint this exists to protect.
     */
    @Test
    void aListOfClaimCannotBeReadBack() {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("amr", List.of("pwd"));

        Exception thrown = assertThrows(Exception.class, () -> roundTrip(claims));

        assertTrue(thrown.getMessage().contains("ImmutableCollections"),
                "expected the validator to name the offending type, got: " + thrown.getMessage());
    }

    /** What the customizer actually puts on a token, kept in step with it by construction. */
    private static List<String> storableAmr() {
        return new ArrayList<>(List.of("pwd"));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> roundTrip(Map<String, Object> claims) {
        String json = mapper.writeValueAsString(claims);
        return mapper.readValue(json, TypeFactory.createDefaultInstance()
                .constructMapType(LinkedHashMap.class, String.class, Object.class));
    }
}
