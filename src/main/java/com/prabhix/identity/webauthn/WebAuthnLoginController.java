package com.prabhix.identity.webauthn;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.oauth.HostedSignIn;
import com.webauthn4j.converter.util.ObjectConverter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.Map;

/**
 * Hosted-login passkey ceremony endpoints.
 *
 * <p>JSON rather than form posts, because the browser hands back a structured credential object that
 * does not fit a form field cleanly. Still on the login UI security chain so CSRF applies and the
 * session that holds the challenge is the same one {@link HostedSignIn} upgrades.
 */
@Slf4j
@RestController
@RequestMapping("/login/passkey")
@RequiredArgsConstructor
public class WebAuthnLoginController {

    private final WebAuthnService webAuthn;
    private final HostedSignIn hostedSignIn;
    private final ObjectConverter objectConverter = new ObjectConverter();

    @PostMapping(value = "/options", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> options(@RequestBody(required = false) PasskeyOptionsRequest body,
                                       HttpSession session) {
        String email = body == null ? null : body.email();
        return webAuthn.beginAssertion(email, session);
    }

    @PostMapping(value = "/verify", consumes = MediaType.APPLICATION_JSON_VALUE)
    public void verify(@RequestBody PasskeyVerifyRequest body,
                       HttpServletRequest request,
                       HttpServletResponse response,
                       HttpSession session) throws IOException, ServletException {
        try {
            String credentialJson = objectConverter.getJsonConverter().writeValueAsString(body.credential());
            hostedSignIn.completeAndRedirect(
                    webAuthn.finishAssertion(credentialJson, session),
                    FactorGrantedAuthority.WEBAUTHN_AUTHORITY,
                    request,
                    response);
        } catch (ApiException ex) {
            log.debug("Passkey sign-in rejected: {}", ex.getMessage());
            response.sendRedirect("/login?error");
        }
    }

    public record PasskeyOptionsRequest(String email) {
    }

    public record PasskeyVerifyRequest(Map<String, Object> credential) {
    }
}
