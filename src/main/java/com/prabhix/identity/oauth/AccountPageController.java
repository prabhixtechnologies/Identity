package com.prabhix.identity.oauth;

import com.prabhix.identity.account.AccountService;
import com.prabhix.identity.account.AccountService.AccountSnapshot;
import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.session.SessionService;
import com.prabhix.identity.user.IdentityUser;
import com.prabhix.identity.web.AuthDtos.ProfileUpdateRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.UUID;

/**
 * The one account page every Prabhix product deep-links to.
 *
 * <p>Products do not grow a settings screen of their own for password, passkeys or email. They send
 * the browser here with {@code return_to} set to a redirect URI they already registered, and this
 * page is what makes "Manage account" the same place from the console, Mailroom and a phone.
 *
 * <p>Cookie session, same chain as {@code /login}. A bearer token is the API; a browser that just
 * signed in already has a session here, and asking it to mint a token just to change a name would
 * be a second dance for nothing.
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class AccountPageController {

    private static final String RETURN_TO_ATTR = "account.return_to";

    private final AccountService accounts;
    private final SessionService sessions;
    private final ReturnToAllowList returnTo;

    @GetMapping("/account")
    public String page(@RequestParam(name = "return_to", required = false) String returnToParam,
                       @RequestParam(required = false) String saved,
                       @RequestParam(required = false) String error,
                       @RequestParam(required = false) String view,
                       Authentication authentication,
                       HttpServletRequest request,
                       Model model) {
        UUID userId = userId(authentication);
        returnTo.validated(returnToParam).ifPresent(url ->
                request.getSession().setAttribute(RETURN_TO_ATTR, url));
        AccountSnapshot snapshot;
        try {
            snapshot = accounts.snapshot(userId);
        } catch (ApiException ex) {
            return "redirect:/login?error";
        }
        IdentityUser user = snapshot.user();
        model.addAttribute("user", user);
        model.addAttribute("passkeys", snapshot.passkeys());
        model.addAttribute("google", snapshot.google());
        model.addAttribute("googleLinked", snapshot.googleLinked());
        model.addAttribute("deletionDueAt", snapshot.deletionDueAt());
        model.addAttribute("sessions", sessions.listActive(userId));
        model.addAttribute("returnTo", currentReturnTo(request.getSession()));
        model.addAttribute("hasPassword", user.hasPassword());
        model.addAttribute("onlyFactorIsGoogle", snapshot.googleLinked()
                && !user.hasPassword()
                && snapshot.passkeys().isEmpty());
        model.addAttribute("onlyFactorIsPasskey", !snapshot.googleLinked()
                && !user.hasPassword()
                && snapshot.passkeys().size() == 1);
        model.addAttribute("view", resolveView(view, saved, error));
        if (saved != null) {
            model.addAttribute("notice", noticeFor(saved));
        }
        if (error != null) {
            model.addAttribute("error", error);
        }
        return "account";
    }

    /**
     * Public because the token in the query string is the proof, the way {@code /login/link} is.
     * Lands on this origin so the session cookie, if any, is already here after the address changes.
     */
    @GetMapping("/account/email/confirm")
    public String confirmEmail(@RequestParam String token,
                               Authentication authentication,
                               HttpServletRequest request) {
        try {
            accounts.confirmEmailChange(token);
        } catch (ApiException ex) {
            log.debug("Email-change link rejected: {}", ex.getMessage());
            if (authentication != null && authentication.isAuthenticated()) {
                return redirectAccount(request, null, ex.getMessage(), "profile");
            }
            return "redirect:/login?error=expired";
        }
        if (authentication != null && authentication.isAuthenticated()) {
            return redirectAccount(request, "email", null, "profile");
        }
        return "redirect:/login";
    }

    @PostMapping("/account/password")
    public String changePassword(@RequestParam(required = false) String currentPassword,
                                 @RequestParam String newPassword,
                                 Authentication authentication,
                                 HttpServletRequest request) {
        UUID userId = userId(authentication);
        try {
            if (accounts.snapshot(userId).user().hasPassword()) {
                accounts.changePassword(userId, currentPassword, newPassword);
            } else {
                accounts.setPasswordFromHosted(userId, newPassword);
            }
            return redirectAccount(request, "password", null, "security");
        } catch (ApiException ex) {
            return redirectAccount(request, null, ex.getMessage(), "security");
        }
    }

    @PostMapping("/account/profile")
    public String updateProfile(@RequestParam String name,
                                @RequestParam(required = false) String displayName,
                                @RequestParam(required = false) String phone,
                                @RequestParam(required = false) String timezone,
                                @RequestParam(required = false) String locale,
                                Authentication authentication,
                                HttpServletRequest request) {
        try {
            accounts.updateProfile(userId(authentication),
                    new ProfileUpdateRequest(name, displayName, phone, timezone, locale));
            return redirectAccount(request, "profile", null, "profile");
        } catch (ApiException ex) {
            return redirectAccount(request, null, ex.getMessage(), "profile");
        }
    }

    @PostMapping("/account/email/change")
    public String requestEmailChange(@RequestParam String email,
                                     Authentication authentication,
                                     HttpServletRequest request) {
        try {
            accounts.requestEmailChange(userId(authentication), email, request.getRemoteAddr());
            return redirectAccount(request, "email-sent", null, "profile");
        } catch (ApiException ex) {
            return redirectAccount(request, null, ex.getMessage(), "profile");
        }
    }

    @PostMapping("/account/passkeys/remove")
    public String removePasskey(@RequestParam UUID id,
                                Authentication authentication,
                                HttpServletRequest request) {
        try {
            accounts.removePasskey(userId(authentication), id);
            return redirectAccount(request, "passkey", null, "security");
        } catch (ApiException ex) {
            return redirectAccount(request, null, ex.getMessage(), "security");
        }
    }

    @PostMapping("/account/identities/google/unlink")
    public String unlinkGoogle(Authentication authentication, HttpServletRequest request) {
        try {
            accounts.unlinkGoogle(userId(authentication));
            return redirectAccount(request, "google", null, "connected");
        } catch (ApiException ex) {
            return redirectAccount(request, null, ex.getMessage(), "connected");
        }
    }

    @PostMapping("/account/sessions/revoke")
    public String revokeSession(@RequestParam UUID id,
                                Authentication authentication,
                                HttpServletRequest request) {
        try {
            sessions.revokeOwn(userId(authentication), id);
            return redirectAccount(request, "session", null, "sessions");
        } catch (ApiException ex) {
            return redirectAccount(request, null, ex.getMessage(), "sessions");
        }
    }

    @PostMapping("/account/deletion")
    public String requestDeletion(Authentication authentication, HttpServletRequest request) {
        accounts.requestDeletion(userId(authentication));
        return redirectAccount(request, "deletion", null, "deletion");
    }

    @PostMapping("/account/deletion/cancel")
    public String cancelDeletion(Authentication authentication, HttpServletRequest request) {
        accounts.cancelDeletion(userId(authentication));
        return redirectAccount(request, "deletion-cancelled", null, "deletion");
    }

    private static UUID userId(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated() || authentication.getName() == null) {
            throw ApiException.of(ErrorCode.UNAUTHENTICATED, "Sign in to continue");
        }
        try {
            return UUID.fromString(authentication.getName());
        } catch (IllegalArgumentException ex) {
            throw ApiException.of(ErrorCode.UNAUTHENTICATED, "Sign in to continue");
        }
    }

    private static String currentReturnTo(HttpSession session) {
        Object stored = session == null ? null : session.getAttribute(RETURN_TO_ATTR);
        return stored instanceof String url ? url : null;
    }

    private static String redirectAccount(HttpServletRequest request, String saved, String error, String view) {
        StringBuilder target = new StringBuilder("/account");
        boolean first = true;
        String returnTo = currentReturnTo(request.getSession(false));
        if (returnTo != null) {
            target.append(first ? '?' : '&').append("return_to=").append(urlEncode(returnTo));
            first = false;
        }
        String pane = view != null ? view : viewForNotice(saved);
        if (pane != null) {
            target.append(first ? '?' : '&').append("view=").append(pane);
            first = false;
        }
        if (saved != null) {
            target.append(first ? '?' : '&').append("saved=").append(saved);
            first = false;
        }
        if (error != null) {
            target.append(first ? '?' : '&').append("error=").append(urlEncode(error));
        }
        return "redirect:" + target;
    }

    static String resolveView(String view, String saved, String error) {
        String fromParam = canonicalView(view);
        if (fromParam != null) {
            return fromParam;
        }
        String fromSaved = viewForNotice(saved);
        if (fromSaved != null) {
            return fromSaved;
        }
        if (error != null) {
            String lower = error.toLowerCase();
            if (lower.contains("password") || lower.contains("passkey")) {
                return "security";
            }
            if (lower.contains("google")) {
                return "connected";
            }
        }
        return "profile";
    }

    private static String canonicalView(String view) {
        if (view == null) {
            return null;
        }
        return switch (view) {
            case "profile", "security", "sessions", "connected", "deletion" -> view;
            default -> null;
        };
    }

    private static String viewForNotice(String saved) {
        if (saved == null) {
            return null;
        }
        return switch (saved) {
            case "password", "passkey", "passkey-added" -> "security";
            case "session" -> "sessions";
            case "google" -> "connected";
            case "deletion", "deletion-cancelled" -> "deletion";
            case "profile", "email", "email-sent" -> "profile";
            default -> null;
        };
    }

    private static String urlEncode(String value) {
        return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8);
    }

    private static String noticeFor(String saved) {
        return switch (saved) {
            case "password" -> "Your password has been updated.";
            case "profile" -> "Your profile has been updated.";
            case "email" -> "Your email has been updated.";
            case "email-sent" -> "Check the new address for a confirmation link.";
            case "passkey" -> "That passkey has been removed.";
            case "passkey-added" -> "Passkey added.";
            case "google" -> "Google is no longer connected.";
            case "session" -> "That session has been signed out.";
            case "deletion" -> "Your account is scheduled for deletion. You can cancel during the grace period.";
            case "deletion-cancelled" -> "Account deletion has been cancelled.";
            default -> null;
        };
    }
}
