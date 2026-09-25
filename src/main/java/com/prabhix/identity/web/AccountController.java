package com.prabhix.identity.web;

import com.prabhix.identity.account.AccountService;
import com.prabhix.identity.security.AuthenticatedCaller;
import com.prabhix.identity.security.RequestMetadata;
import com.prabhix.identity.web.AuthDtos.AckResponse;
import com.prabhix.identity.web.AuthDtos.EmailChangeConfirmRequest;
import com.prabhix.identity.web.AuthDtos.EmailChangeRequest;
import com.prabhix.identity.web.AuthDtos.PasswordChangeRequest;
import com.prabhix.identity.web.AuthDtos.ProfileUpdateRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Self-service account changes, for a signed-in bearer or hosted session.
 *
 * <p>Not the hosted {@code /account} page — that is a document with a cookie session. These are the
 * JSON paths products and that page's fetch calls share. Email-change confirm is the exception: it
 * is public because the secret in the link is the proof, the way a magic link is.
 */
@RestController
@RequestMapping("/api/v1/identity/auth")
@RequiredArgsConstructor
public class AccountController {

    private final AccountService accounts;

    /**
     * Changes the password and leaves this session alone.
     *
     * <p>{@code CredentialService.setPassword} revokes everything issued before the change, which is
     * right for a reset from a mailed link and wrong here: the person who just typed the current
     * password expects to stay signed in.
     */
    @PostMapping("/password/change")
    public AckResponse changePassword(@AuthenticationPrincipal AuthenticatedCaller caller,
                                      @Valid @RequestBody PasswordChangeRequest request) {
        return accounts.changePassword(caller.userId(), request.currentPassword(), request.newPassword());
    }

    @PutMapping("/profile")
    public AckResponse updateProfile(@AuthenticationPrincipal AuthenticatedCaller caller,
                                     @Valid @RequestBody ProfileUpdateRequest request) {
        return accounts.updateProfile(caller.userId(), request);
    }

    @PostMapping("/email/change/request")
    public AckResponse requestEmailChange(@AuthenticationPrincipal AuthenticatedCaller caller,
                                          @Valid @RequestBody EmailChangeRequest request,
                                          HttpServletRequest http) {
        return accounts.requestEmailChange(caller.userId(), request.email(), RequestMetadata.clientIp(http));
    }

    @PostMapping("/email/change/confirm")
    public AckResponse confirmEmailChange(@Valid @RequestBody EmailChangeConfirmRequest request) {
        return accounts.confirmEmailChange(request.token());
    }

    @DeleteMapping("/identities/google")
    public void unlinkGoogle(@AuthenticationPrincipal AuthenticatedCaller caller) {
        accounts.unlinkGoogle(caller.userId());
    }

    @PostMapping("/deletion")
    public AckResponse requestDeletion(@AuthenticationPrincipal AuthenticatedCaller caller) {
        return accounts.requestDeletion(caller.userId());
    }

    @DeleteMapping("/deletion")
    public AckResponse cancelDeletion(@AuthenticationPrincipal AuthenticatedCaller caller) {
        return accounts.cancelDeletion(caller.userId());
    }
}
