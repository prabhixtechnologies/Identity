package com.prabhix.identity.security;

import com.prabhix.identity.config.IdentityProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class FirstPartyHttpOriginsTest {

    @Test
    @DisplayName("form-action lists AppAuth custom schemes so Chrome can return to the Android app")
    void formActionIncludesMobileSchemes() {
        IdentityProperties properties = properties(
                new IdentityProperties.Client(
                        "prabhix-mobistack-android",
                        "MobiStack Android",
                        "",
                        List.of("mobistack://oauth2redirect", "mobistack:/oauth2redirect"),
                        List.of("mobistack://oauth2redirect"),
                        List.of("openid", "profile", "email"),
                        true),
                new IdentityProperties.Client(
                        "prabhix-admin-android",
                        "Admin Android",
                        "",
                        List.of("com.prabhix.admin:/oauth2redirect"),
                        List.of(),
                        List.of("openid"),
                        true));

        List<String> sources = FirstPartyHttpOrigins.formActionSources(properties);

        assertThat(sources).contains("'self'", "mobistack:", "com.prabhix.admin:",
                "http://localhost:5173", "http://localhost:5174");
        assertThat(FirstPartyHttpOrigins.loginCsp(properties))
                .contains("form-action")
                .contains("mobistack:")
                .contains("com.prabhix.admin:");
    }

    @Test
    @DisplayName("CORS origins stay HTTP(S) only — custom schemes are not browser origins")
    void corsOriginsSkipCustomSchemes() {
        IdentityProperties properties = properties(
                new IdentityProperties.Client(
                        "prabhix-mobistack-android",
                        "MobiStack Android",
                        "",
                        List.of("mobistack://oauth2redirect", "https://mobistack.prabhixtechnologies.com/auth/callback"),
                        List.of(),
                        List.of("openid"),
                        true));

        assertThat(FirstPartyHttpOrigins.from(properties))
                .contains("https://mobistack.prabhixtechnologies.com")
                .noneMatch(origin -> origin.startsWith("mobistack"));
    }

    private static IdentityProperties properties(IdentityProperties.Client... clients) {
        return new IdentityProperties(
                "https://api.prabhixtechnologies.com",
                null,
                null,
                null,
                null,
                null,
                null,
                new IdentityProperties.Urls("http://localhost:5173", "http://localhost:5174"),
                null,
                null,
                null,
                null,
                null,
                List.of(clients),
                null,
                null);
    }
}
