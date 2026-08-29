package com.prabhix.identity.security;

import com.prabhix.identity.token.IdentityClaims;
import com.prabhix.identity.token.TokenDenyList;
import com.prabhix.identity.token.TokenService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * Authenticates the few endpoints here that need a signed-in caller: {@code /auth/me},
 * {@code /auth/logout}, session management and email-verification requests.
 *
 * <p>Verifies against our own signing key rather than the published JWKS, which is what every
 * product does. Fetching our own key over HTTP from ourselves would add a failure mode for nothing.
 *
 * <p>The single authority granted is {@code ROLE_USER}. This service has no permission model on
 * purpose — knowing who someone is and deciding what they may do are the two halves the split was
 * for, and a role table here would grow into the distributed monolith it was meant to avoid.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class IdentityAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER = "Bearer ";

    private final TokenService tokens;
    private final TokenDenyList denyList;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith(BEARER)) {
            chain.doFilter(request, response);
            return;
        }

        try {
            TokenService.VerifiedToken verified =
                    tokens.verified(header.substring(BEARER.length()).trim());
            IdentityClaims claims = verified.claims();

            // Checked here as well as in each product. A token revoked by a logout must not still
            // work against the endpoint that lists and revokes sessions.
            if (denyList.isRevoked(claims.subject(), claims.sessionId(), verified.issuedAt())) {
                log.debug("Rejecting a revoked token for session {}", claims.sessionId());
                chain.doFilter(request, response);
                return;
            }

            AuthenticatedCaller caller = new AuthenticatedCaller(claims.subject(), claims.sessionId());
            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken(caller, null,
                            List.of(new SimpleGrantedAuthority("ROLE_USER"))));
        } catch (ExpiredJwtException ex) {
            // Left unauthenticated rather than rejected outright: Spring Security's entry point
            // produces the 401, so there is one place that shapes an unauthenticated response.
            log.debug("Expired token presented to {}", request.getRequestURI());
        } catch (JwtException | IllegalArgumentException ex) {
            log.debug("Unusable token presented to {}: {}", request.getRequestURI(), ex.getMessage());
        }

        chain.doFilter(request, response);
    }
}
