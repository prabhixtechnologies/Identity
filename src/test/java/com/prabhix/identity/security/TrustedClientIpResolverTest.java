package com.prabhix.identity.security;

import com.prabhix.identity.config.TestProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TrustedClientIpResolverTest {

    @Test
    void ignoresForwardedForFromUntrustedPeers() {
        TrustedClientIpResolver resolver = new TrustedClientIpResolver(TestProperties.signing("", List.of()));
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenReturn("203.0.113.10");
        when(request.getHeader("X-Forwarded-For")).thenReturn("198.51.100.4");

        assertThat(resolver.resolve(request)).isEqualTo("203.0.113.10");
    }

    @Test
    void honoursForwardedForFromTrustedPeers() {
        TrustedClientIpResolver resolver = new TrustedClientIpResolver(TestProperties.signing("", List.of()));
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenReturn("127.0.0.1");
        when(request.getHeader("X-Forwarded-For")).thenReturn("198.51.100.4, 127.0.0.1");

        assertThat(resolver.resolve(request)).isEqualTo("198.51.100.4");
    }
}
