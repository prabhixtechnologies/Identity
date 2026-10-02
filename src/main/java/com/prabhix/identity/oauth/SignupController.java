package com.prabhix.identity.oauth;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.provisioning.SignupService;
import com.prabhix.identity.provisioning.SignupVerificationService;
import com.prabhix.identity.user.IdentityUser;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;
import java.util.Set;
import java.util.UUID;

/**
 * Creating an account, on the same origin as signing into one.
 *
 * <p>Here for the same reason the login page is: whatever sets the session cookie has to be this
 * origin, or the person who just signed up is signed in to nothing. It also means no product needs a
 * password field of its own — a console that never sees a password cannot leak one, and there is one
 * place to change if what a password has to be ever changes.
 *
 * <p>Ends in a live session and resumes whatever authorization request was waiting, so signing up and
 * then being asked to sign in — which is what a signup form in a console does — does not happen.
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class SignupController {

    private static final Set<String> SHOP_LATER_CLIENTS = Set.of(
            "prabhix-mobistack", "prabhix-mobistack-android");

    private final SignupService signup;
    private final SignupVerificationService verification;
    private final HostedSignIn hostedSignIn;
    private final SignInBrand brands;
    private final HttpSessionRequestCache savedRequests = new HttpSessionRequestCache();
    private static final String PENDING_USER = "signup.pending.user";
    private static final String PENDING_EMAIL = "signup.pending.email";

    @GetMapping("/signup")
    public String form(@RequestParam(required = false) String email,
                       @RequestParam(required = false) String name,
                       @RequestParam(required = false) String organization,
                       HttpServletRequest request,
                       HttpServletResponse response,
                       Model model) {
        boolean shopLater = shopLater(request, response);
        model.addAttribute("email", email != null ? email : "");
        model.addAttribute("name", name != null ? name : "");
        model.addAttribute("organization", organization != null ? organization : "");
        model.addAttribute("shopLater", shopLater);
        // A deployment with no platform to provision against cannot honestly offer signup: it would
        // take a password, create an account, and then withdraw it. The page says so instead.
        // MobiStack does not need that platform call, so its signup stays open without it.
        model.addAttribute("available", shopLater || signup.available());
        model.addAttribute("brand", brands.forRequest(request, response));
        return "signup";
    }

    /**
     * Creates the account and its workspace, then signs the browser in.
     *
     * <p>Redisplays the form on failure with everything except the password still filled in. Losing a
     * typed organization name and full name to a rejected password is a small thing that reads as the
     * page not working, and re-typing an address is where people give up.
     */
    @PostMapping("/signup")
    public String create(@RequestParam String email,
                         @RequestParam String password,
                         @RequestParam String name,
                         @RequestParam(required = false) String organization,
                         HttpServletRequest request,
                         HttpServletResponse response,
                         Model model) throws IOException, ServletException {
        boolean shopLater = shopLater(request, response);
        if (!shopLater && (organization == null || organization.isBlank())) {
            model.addAttribute("error", "A workspace name is required.");
            model.addAttribute("email", email);
            model.addAttribute("name", name);
            model.addAttribute("organization", "");
            model.addAttribute("shopLater", false);
            model.addAttribute("available", signup.available());
            model.addAttribute("brand", brands.forRequest(request, response));
            return "signup";
        }
        try {
            IdentityUser user = signup.createAccount(email, password, name);
            try {
                verification.send(user, request.getRemoteAddr());
                // Provision only after mail was accepted, so an undeliverable OTP cannot leave an
                // orphan workspace. It happens before the code is entered so abandoning this tab can
                // be recovered through the normal emailed-code sign-in without losing the workspace.
                signup.provision(user, shopLater ? null : organization.trim());
            } catch (RuntimeException incompleteSignup) {
                signup.withdrawIncomplete(user);
                throw incompleteSignup;
            }
            request.getSession().setAttribute(PENDING_USER, user.getId());
            request.getSession().setAttribute(PENDING_EMAIL, user.getEmail());
            return verificationPage(user.getEmail(), null, request, response, model);
        } catch (ApiException ex) {
            // Passed through rather than replaced by one generic line, unlike the login page. The
            // reasons here are all things the person can act on — the address is taken, the password is
            // too short — and none of them reveals anything they could not find out by trying to sign
            // in. Withholding them would leave a form that refuses without saying why.
            log.info("Signup rejected for {}: {}", email, ex.getMessage());
            model.addAttribute("error", ex.getMessage());
            model.addAttribute("email", email);
            model.addAttribute("name", name);
            model.addAttribute("organization", organization);
            model.addAttribute("shopLater", shopLater);
            model.addAttribute("available", shopLater || signup.available());
            model.addAttribute("brand", brands.forRequest(request, response));
            return "signup";
        }
    }

    @PostMapping("/signup/verify")
    public String verify(@RequestParam String code,
                         HttpServletRequest request,
                         HttpServletResponse response,
                         Model model) throws IOException, ServletException {
        UUID userId = pendingUser(request);
        String email = (String) request.getSession().getAttribute(PENDING_EMAIL);
        if (userId == null || email == null) {
            return "redirect:/signup";
        }
        try {
            IdentityUser user = verification.verify(userId, email, code);
            clearPending(request);
            // The OTP is the factor that activated this account; the password was only chosen.
            hostedSignIn.completeAndRedirect(
                    user, FactorGrantedAuthority.OTT_AUTHORITY, request, response);
            return null;
        } catch (ApiException ex) {
            return verificationPage(email, ex.getMessage(), request, response, model);
        }
    }

    @PostMapping("/signup/resend")
    public String resend(HttpServletRequest request,
                         HttpServletResponse response,
                         Model model) {
        UUID userId = pendingUser(request);
        String email = (String) request.getSession().getAttribute(PENDING_EMAIL);
        if (userId == null || email == null) {
            return "redirect:/signup";
        }
        try {
            verification.resend(userId, request.getRemoteAddr());
            model.addAttribute("notice", "A new code was sent.");
            return verificationPage(email, null, request, response, model);
        } catch (ApiException ex) {
            return verificationPage(email, ex.getMessage(), request, response, model);
        }
    }

    private String verificationPage(String email, String error,
                                    HttpServletRequest request, HttpServletResponse response,
                                    Model model) {
        model.addAttribute("email", email);
        model.addAttribute("error", error);
        model.addAttribute("brand", brands.forRequest(request, response));
        return "signup-verify";
    }

    private UUID pendingUser(HttpServletRequest request) {
        Object value = request.getSession().getAttribute(PENDING_USER);
        return value instanceof UUID id ? id : null;
    }

    private void clearPending(HttpServletRequest request) {
        request.getSession().removeAttribute(PENDING_USER);
        request.getSession().removeAttribute(PENDING_EMAIL);
    }

    /** MobiStack's authorize request is what was saved before this page opened. */
    private boolean shopLater(HttpServletRequest request, HttpServletResponse response) {
        SavedRequest saved = savedRequests.getRequest(request, response);
        if (saved == null) {
            return false;
        }
        String[] clientIds = saved.getParameterValues("client_id");
        if (clientIds == null) {
            return false;
        }
        for (String clientId : clientIds) {
            if (SHOP_LATER_CLIENTS.contains(clientId)) {
                return true;
            }
        }
        return false;
    }
}
