package com.prabhix.identity.security.internal;

import com.prabhix.identity.common.ApiError;
import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import tools.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/** First gate on every {@code /internal} request before controller logic runs. */
@Component
@RequiredArgsConstructor
public class InternalServiceAuthFilter extends OncePerRequestFilter {

    private final InternalServiceAuthValidator validator;
    private final ObjectMapper objectMapper;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !InternalRoutePolicy.isInternal(request);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        try {
            validator.verify(request, true);
            chain.doFilter(request, response);
        } catch (ApiException ex) {
            response.setStatus(ex.getCode().status().value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            objectMapper.writeValue(response.getOutputStream(), ApiError.of(
                    ex.getCode(),
                    ex.getMessage(),
                    null,
                    request.getRequestURI()));
        }
    }
}
