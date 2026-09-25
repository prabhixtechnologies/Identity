package com.prabhix.identity.oauth;

import com.prabhix.identity.web.AuthDtos.AckResponse;
import com.prabhix.identity.webauthn.WebAuthnService;
import com.webauthn4j.converter.util.ObjectConverter;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.UUID;

/**
 * Passkey enrolment from the hosted account page.
 *
 * <p>Same ceremony as {@code /api/v1/identity/webauthn/register}, on this chain so the login session and the
 * CSRF token apply. The API chain is stateless and would not see the cookie that got the browser
 * here.
 */
@RestController
@RequestMapping("/account/passkey")
@RequiredArgsConstructor
public class HostedAccountPasskeyController {

    private final WebAuthnService webAuthn;
    private final ObjectConverter objectConverter = new ObjectConverter();

    @PostMapping(value = "/options", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> options(Authentication authentication) {
        return webAuthn.beginRegistration(userId(authentication));
    }

    @PostMapping(value = "/finish", consumes = MediaType.APPLICATION_JSON_VALUE)
    public AckResponse finish(Authentication authentication, @Valid @RequestBody FinishRequest request) {
        String credentialJson = objectConverter.getJsonConverter().writeValueAsString(request.credential());
        webAuthn.finishRegistration(userId(authentication), credentialJson, request.label());
        return new AckResponse("Passkey registered.");
    }

    private static UUID userId(Authentication authentication) {
        return UUID.fromString(authentication.getName());
    }

    public record FinishRequest(@NotNull Map<String, Object> credential, String label) {
    }
}
