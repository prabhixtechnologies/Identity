package com.prabhix.identity.oauth;

import com.prabhix.identity.challenge.PasswordlessService;
import com.prabhix.identity.challenge.PhoneAuthService;
import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.config.IdentityProperties;
import com.prabhix.identity.sso.GoogleSsoService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.UriUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * The one sign-in page for every Prabhix product.
 *
 * <p>Six ways in, all landing in the same place: a session cookie on this origin, and then whatever
 * authorization request was waiting. Password is handled by Spring Security's form login at
 * {@code POST /login}; the other five are the methods below, because each has to verify its own kind
 * of proof before {@link HostedSignIn} can establish the session.
 *
 * <p>Methods that need credentials this deployment does not have — Google without a client id, SMS
 * without a Twilio account — are not rendered at all. A visible button that returns "not enabled" is
 * worse than an absent one: it reads as a fault in the product rather than a feature nobody bought.
 *
 * <p>Every failure that involves an address answers the same way whether or not the address has an
 * account. The page would otherwise be a membership oracle, answering "is this person a customer"
 * one guess at a time.
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class LoginController {

    /** One message for every credential failure, for the reason above. */
    private static final String GENERIC_FAILURE = "Those details do not match an account.";

    private final IdentityProperties properties;
    private final PasswordlessService passwordless;
    private final PhoneAuthService phones;
    private final GoogleSsoService google;
    private final HostedSignIn hostedSignIn;

    @GetMapping("/login")
    public String login(@RequestParam(required = false) String error,
                        @RequestParam(required = false) String signedOut,
                        @RequestParam(required = false) String sent,
                        @RequestParam(required = false) String code,
                        @RequestParam(required = false) String phone,
                        @RequestParam(required = false) String email,
                        @RequestParam(required = false) String number,
                        @RequestParam(required = false) String method,
                        Model model) {
        if (error != null) {
            model.addAttribute("error", GENERIC_FAILURE);
        }
        if ("expired".equals(error)) {
            model.addAttribute("error", "That link has already been used, or has expired.");
        }
        if (signedOut != null) {
            model.addAttribute("notice", "You have been signed out.");
        }
        if ("link".equals(sent)) {
            model.addAttribute("notice",
                    "If that address is registered, a sign-in link is on its way. It expires shortly.");
        }
        if (sent != null && phone != null) {
            model.addAttribute("notice", "If that number has an account, a code is on its way.");
        }

        // Which step the page opens on. Held in the query string rather than the session so that a
        // reload, or the browser's back button, shows what it did before.
        //
        // `choose` requires an address: without one, step two would ask for a password and post a
        // blank username, which fails as bad credentials rather than as the missing field it is.
        boolean identified = email != null && !email.isBlank();
        model.addAttribute("stage",
                code != null ? "code"
                        : phone != null ? "phone"
                        : "choose".equals(method) && identified ? "choose"
                        : "identify");
        model.addAttribute("email", email != null ? email : "");
        model.addAttribute("number", number != null ? number : "");
        model.addAttribute("googleClientId", google.enabled() ? google.clientId() : null);
        model.addAttribute("phoneEnabled", phones.enabled());
        model.addAttribute("forgotPasswordUrl", properties.urls().console() + "/forgot-password");
        return "login";
    }

    /** Sends a link that signs the browser in when opened. */
    @PostMapping("/login/link")
    public String requestLink(@RequestParam String email, HttpServletRequest request) {
        passwordless.requestMagicLink(email, request.getRemoteAddr());
        return "redirect:/login?sent=link";
    }

    /**
     * Opens a magic link.
     *
     * <p>A GET that changes state, which is normally wrong and is unavoidable here: this URL arrives
     * in an email, and an email client can only issue a GET. The token is single-use, which is what
     * keeps a prefetching mail client from being able to replay it.
     */
    @GetMapping("/login/link")
    public String openLink(@RequestParam String token,
                           HttpServletRequest request,
                           HttpServletResponse response) throws IOException, ServletException {
        try {
            hostedSignIn.completeAndRedirect(passwordless.authenticateByMagicLink(token),
                    FactorGrantedAuthority.OTT_AUTHORITY, request, response);
            return null;
        } catch (ApiException ex) {
            log.debug("Magic link rejected: {}", ex.getMessage());
            return "redirect:/login?error=expired";
        }
    }

    /** Sends a short code to type back in, for people who cannot follow a link where they are. */
    @PostMapping("/login/code")
    public String requestCode(@RequestParam String email, HttpServletRequest request) {
        passwordless.requestOtp(email, request.getRemoteAddr());
        return "redirect:/login?code&email=" + encode(email);
    }

    @PostMapping("/login/code/verify")
    public String verifyCode(@RequestParam String email,
                             @RequestParam String code,
                             HttpServletRequest request,
                             HttpServletResponse response) throws IOException, ServletException {
        try {
            hostedSignIn.completeAndRedirect(passwordless.authenticateByOtp(email, code),
                    FactorGrantedAuthority.OTT_AUTHORITY, request, response);
            return null;
        } catch (ApiException ex) {
            log.debug("Emailed code rejected: {}", ex.getMessage());
            return "redirect:/login?code&email=" + encode(email) + "&error";
        }
    }

    @PostMapping("/login/phone")
    public String requestPhoneCode(@RequestParam String phone, HttpServletRequest request) {
        try {
            phones.requestOtp(phone, request.getRemoteAddr());
        } catch (ApiException ex) {
            // A malformed number is worth saying out loud — unlike an unknown one, it is the caller's
            // typo and telling them reveals nothing about who has an account.
            return "redirect:/login?phone&error";
        }
        // The number rides along so the code form below it knows what to verify against. It is what
        // the person just typed, not a lookup, so echoing it discloses nothing.
        return "redirect:/login?phone&sent=1&number=" + encode(phone);
    }

    @PostMapping("/login/phone/verify")
    public String verifyPhoneCode(@RequestParam String phone,
                                  @RequestParam String code,
                                  HttpServletRequest request,
                                  HttpServletResponse response) throws IOException, ServletException {
        try {
            hostedSignIn.completeAndRedirect(phones.authenticateByOtp(phone, code),
                    FactorGrantedAuthority.OTT_AUTHORITY, request, response);
            return null;
        } catch (ApiException ex) {
            log.debug("SMS code rejected: {}", ex.getMessage());
            return "redirect:/login?phone&error&number=" + encode(phone);
        }
    }

    /**
     * Completes Google sign-in.
     *
     * <p>Posted by our own script rather than by Google directly. Google's button can POST straight to
     * a {@code login_uri}, but that request is cross-site and carries no CSRF token, so it would have
     * to be exempted — and an exempt endpoint that signs somebody in on a posted credential is worth
     * avoiding. The script hands the credential to a same-origin form instead.
     */
    @PostMapping("/login/google")
    public String google(@RequestParam String credential,
                         HttpServletRequest request,
                         HttpServletResponse response) throws IOException, ServletException {
        try {
            // Google proved this with its own authorization code flow, so that is the factor to
            // record — not OTT, which would claim we mailed them something.
            hostedSignIn.completeAndRedirect(google.authenticate(credential),
                    FactorGrantedAuthority.AUTHORIZATION_CODE_AUTHORITY, request, response);
            return null;
        } catch (ApiException ex) {
            log.debug("Google credential rejected: {}", ex.getMessage());
            return "redirect:/login?error";
        }
    }

    private String encode(String value) {
        return UriUtils.encodeQueryParam(value, StandardCharsets.UTF_8);
    }
}
