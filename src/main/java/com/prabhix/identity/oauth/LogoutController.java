package com.prabhix.identity.oauth;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Hosted sign-out for products that share the identity session cookie.
 *
 * <p>{@code GET /logout} never changes server state: it renders a confirmation page with a CSRF token.
 * {@code POST /logout} completes sign-out. Clients such as {@code @prabhixtechnologies/oidc-client} should navigate
 * with {@code GET} (or open this page) rather than posting a bare form without a CSRF token.
 *
 * <p>RP-initiated logout continues to use {@code /connect/logout} on the authorization-server chain.
 */
@Controller
@RequiredArgsConstructor
public class LogoutController {

    private final HostedLogoutService hostedLogout;
    private final ReturnToAllowList returnToAllowList;

    @GetMapping("/logout")
    public String confirm(@RequestParam(required = false) String return_to, Model model) {
        model.addAttribute("returnTo", safeReturnTo(return_to));
        return "logout-confirm";
    }

    @PostMapping("/logout")
    public String complete(HttpServletRequest request,
                           HttpServletResponse response,
                           Authentication authentication,
                           @RequestParam(required = false) String return_to) {
        hostedLogout.signOut(request, response, authentication);
        String target = safeReturnTo(return_to);
        if (target != null) {
            return "redirect:" + target;
        }
        return "redirect:/login?signedOut";
    }

    private String safeReturnTo(String candidate) {
        if (candidate == null || candidate.isBlank()) {
            return null;
        }
        return returnToAllowList.validated(candidate).orElse(null);
    }
}
