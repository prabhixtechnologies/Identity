package com.prabhix.identity.oauth;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

/**
 * Authenticates a public client's refresh-token grant from {@code client_id} alone.
 *
 * <p>Spring's built-in {@code PublicClientAuthenticationConverter} only matches PKCE code exchanges
 * ({@code code_verifier} present). A refresh request has neither a verifier nor a client secret, so
 * without this converter the token endpoint has nothing that can authenticate the caller and the
 * grant fails even after a refresh token was issued.
 *
 * <p>Confidential clients that send {@code client_secret} are left alone — those converters must win.
 */
final class PublicClientRefreshTokenAuthenticationConverter implements AuthenticationConverter {

    @Override
    @Nullable
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(grantType)) {
            return null;
        }
        if (StringUtils.hasText(request.getParameter(OAuth2ParameterNames.CLIENT_SECRET))) {
            return null;
        }

        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        if (!StringUtils.hasText(clientId)) {
            return null;
        }
        // Duplicate client_id is an invalid_request, not a silent pick of the first value.
        String[] values = request.getParameterValues(OAuth2ParameterNames.CLIENT_ID);
        if (values != null && values.length != 1) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }

        return new PublicClientRefreshTokenAuthenticationToken(clientId);
    }

    /**
     * Distinct from {@link OAuth2ClientAuthenticationToken} so the PKCE public-client provider does
     * not claim this authentication and then demand a {@code code_verifier}.
     */
    static final class PublicClientRefreshTokenAuthenticationToken extends OAuth2ClientAuthenticationToken {

        PublicClientRefreshTokenAuthenticationToken(String clientId) {
            super(clientId, ClientAuthenticationMethod.NONE, null, null);
        }

        PublicClientRefreshTokenAuthenticationToken(
                org.springframework.security.oauth2.server.authorization.client.RegisteredClient client) {
            super(client, ClientAuthenticationMethod.NONE, null);
        }
    }
}
