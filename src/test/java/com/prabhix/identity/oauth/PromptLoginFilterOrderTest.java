package com.prabhix.identity.oauth;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.access.ExceptionTranslationFilter;

import java.util.HashMap;

import static org.assertj.core.api.Assertions.assertThatCode;

class PromptLoginFilterOrderTest {

    @Test
    @DisplayName("the step-up filter anchors on a filter Spring Security already knows")
    void installsWithoutARegisteredAuthorizationEndpointOrder() {
        ObjectPostProcessor<Object> postProcessor = new ObjectPostProcessor<>() {
            @Override
            public <O> O postProcess(O object) {
                return object;
            }
        };
        HttpSecurity http = new HttpSecurity(postProcessor, new AuthenticationManagerBuilder(postProcessor), new HashMap<>());

        assertThatCode(() -> http.addFilterBefore(new PromptLoginFilter(), ExceptionTranslationFilter.class))
                .doesNotThrowAnyException();
    }
}
