package com.prabhix.identity.security;

import com.prabhix.identity.token.IdentityClaims;
import com.prabhix.identity.token.TokenDenyList;
import com.prabhix.identity.token.TokenService;
import com.prabhix.identity.user.IdentityUser.UserStatus;
import com.prabhix.identity.user.IdentityUserRepository;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Authenticates the endpoints here that need a signed-in caller: {@code /auth/me},
 * {@code /auth/logout}, session management, and everything under {@code /api/v1/identity/account}.
 *
 * <p>Two ways in, one principal out. A bearer token is verified against our own signing key rather
 * than the published JWKS, which is what every product does — fetching our own key over HTTP from
 * ourselves would add a failure mode for nothing. On the hosted chain, where the browser already has
 * a login session, the session's authentication is re-expressed as the same {@link AuthenticatedCaller}
 * so that a controller serving both the API and the {@code /account} page does not care which it got.
 *
 * <p>Both ways check the account is still allowed in. A token is a claim made at issue time, and a
 * session was opened at sign-in; an account disabled since then must stop working now, not when the
 * token expires or the session times out.
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
    private static final GrantedAuthority ROLE_USER = new SimpleGrantedAuthority("ROLE_USER");

    private final TokenService tokens;
    private final TokenDenyList denyList;
    private final IdentityUserRepository users;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith(BEARER)) {
            bridgeHostedSession();
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
            if (!signInAllowed(claims.subject())) {
                log.debug("Rejecting a token for a disabled or deleted account {}", claims.subject());
                chain.doFilter(request, response);
                return;
            }

            AuthenticatedCaller caller =
                    new AuthenticatedCaller(claims.subject(), claims.sessionId(), verified.clientId());
            SecurityContextHolder.getContext().setAuthentication(authenticated(caller, List.of()));
        } catch (ExpiredJwtException ex) {
            // Left unauthenticated rather than rejected outright: Spring Security's entry point
            // produces the 401, so there is one place that shapes an unauthenticated response.
            log.debug("Expired token presented to {}", request.getRequestURI());
        } catch (JwtException | IllegalArgumentException ex) {
            log.debug("Unusable token presented to {}: {}", request.getRequestURI(), ex.getMessage());
        }

        chain.doFilter(request, response);
    }

    /**
     * Turns a hosted login session into an {@link AuthenticatedCaller} for this request only.
     *
     * <p>The session holds a {@code UsernamePasswordAuthenticationToken} whose name is the user id,
     * written by form login or {@code HostedSignIn}. It is left exactly as it is: the replacement goes
     * into a fresh context on the thread, never back into the session, because the authorization
     * server reads the session's principal name as the {@code sub} claim and must keep finding the
     * bare id there. The factor authorities are carried over so nothing downstream loses them.
     *
     * <p>An account disabled since sign-in gets no principal at all, so the request falls through to
     * the entry point as if the session did not exist.
     */
    private void bridgeHostedSession() {
        Authentication existing = SecurityContextHolder.getContext().getAuthentication();
        if (existing == null
                || !existing.isAuthenticated()
                || existing instanceof AnonymousAuthenticationToken
                || existing.getPrincipal() instanceof AuthenticatedCaller) {
            return;
        }
        UUID userId;
        try {
            userId = UUID.fromString(existing.getName());
        } catch (IllegalArgumentException | NullPointerException ex) {
            return;
        }
        SecurityContext fresh = SecurityContextHolder.createEmptyContext();
        if (signInAllowed(userId)) {
            fresh.setAuthentication(authenticated(new AuthenticatedCaller(userId, null),
                    existing.getAuthorities()));
        } else {
            log.debug("Hosted session for disabled or deleted account {} carries no principal", userId);
        }
        SecurityContextHolder.setContext(fresh);
    }

    private boolean signInAllowed(UUID userId) {
        return users.findByIdAndDeletedAtIsNull(userId)
                .filter(user -> user.getStatus() != UserStatus.DISABLED)
                .isPresent();
    }

    private static Authentication authenticated(AuthenticatedCaller caller,
                                                java.util.Collection<? extends GrantedAuthority> carried) {
        List<GrantedAuthority> authorities = new ArrayList<>(carried);
        authorities.add(ROLE_USER);
        return new UsernamePasswordAuthenticationToken(caller, null, authorities);
    }
}
