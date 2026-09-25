package com.prabhix.identity.webauthn;

import com.prabhix.identity.account.AccountService;
import com.prabhix.identity.security.AuthenticatedCaller;
import com.prabhix.identity.web.AuthDtos.PasskeyView;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/** Listing and removing passkeys the signed-in user already holds. Registration is a sibling. */
@RestController
@RequestMapping("/api/v1/identity/webauthn/credentials")
@RequiredArgsConstructor
public class WebAuthnCredentialController {

    private final AccountService accounts;

    @GetMapping
    public List<PasskeyView> list(@AuthenticationPrincipal AuthenticatedCaller caller) {
        return accounts.listPasskeys(caller.userId());
    }

    @DeleteMapping
    public void remove(@AuthenticationPrincipal AuthenticatedCaller caller, @RequestParam UUID id) {
        accounts.removePasskey(caller.userId(), id);
    }
}
