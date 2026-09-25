package com.prabhix.identity.oauth;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.provisioning.SignupService;
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
    private final HostedSignIn hostedSignIn;
    private final HttpSessionRequestCache savedRequests = new HttpSessionRequestCache();

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
            return "signup";
        }
        try {
            IdentityUser user = signup.signUp(email, password, name, shopLater ? null : organization);
            // A password was typed, so that is the factor — the same one form login would record.
            hostedSignIn.completeAndRedirect(user, FactorGrantedAuthority.PASSWORD_AUTHORITY,
                    request, response);
            // Nothing to render: completeAndRedirect has already written the redirect.
            return null;
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
            return "signup";
        }
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
