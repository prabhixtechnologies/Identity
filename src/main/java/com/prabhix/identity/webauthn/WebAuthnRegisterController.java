package com.prabhix.identity.webauthn;

import com.prabhix.identity.security.AuthenticatedCaller;
import com.prabhix.identity.web.AuthDtos.AckResponse;
import com.webauthn4j.converter.util.ObjectConverter;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Register a passkey from an already-authenticated API client.
 *
 * <p>Bearer-authenticated (same as phone number binding): a passkey created outside a session would
 * be one an attacker registered against somebody else's account after guessing an email.
 */
@RestController
@RequestMapping("/api/v1/identity/webauthn/register")
@RequiredArgsConstructor
public class WebAuthnRegisterController {

    private final WebAuthnService webAuthn;
    private final ObjectConverter objectConverter = new ObjectConverter();

    @PostMapping(value = "/options", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> options(@AuthenticationPrincipal AuthenticatedCaller caller) {
        return webAuthn.beginRegistration(caller.userId());
    }

    @PostMapping(value = "/finish", consumes = MediaType.APPLICATION_JSON_VALUE)
    public AckResponse finish(@AuthenticationPrincipal AuthenticatedCaller caller,
                              @Valid @RequestBody FinishRequest request) {
        String credentialJson = objectConverter.getJsonConverter().writeValueAsString(request.credential());
        webAuthn.finishRegistration(caller.userId(), credentialJson, request.label());
        return new AckResponse("Passkey registered.");
    }

    public record FinishRequest(@NotNull Map<String, Object> credential, String label) {
    }
}
