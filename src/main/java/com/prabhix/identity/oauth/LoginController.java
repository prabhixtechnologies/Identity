package com.prabhix.identity.oauth;

import com.prabhix.identity.challenge.PasswordlessService;
import com.prabhix.identity.challenge.PhoneAuthService;
import com.prabhix.identity.challenge.WhatsAppAuthService;
import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.config.IdentityProperties;
import com.prabhix.identity.provisioning.SignupService;
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

import java.io.IOException;

/**
 * The one sign-in page for every Prabhix product.
 *
 * <p>Several ways in, all landing in the same place: a session cookie on this origin, and then whatever
 * authorization request was waiting. Password is handled by Spring Security's form login at
 * {@code POST /login}; the other methods are below, because each has to verify its own kind of proof
 * before {@link HostedSignIn} can establish the session.
 *
 * <p>Methods that need credentials this deployment does not have — Google without a client id, SMS
 * without a Twilio account — are not rendered at all. A visible button that returns "not enabled" is
 * worse than an absent one: it reads as a fault in the product rather than a feature nobody bought.
 *
 * <p>Every failure that involves an address answers the same way whether or not the address has an
 * account. The page would otherwise be a membership oracle, answering "is this person a customer"
 * one guess at a time.
 *
 * <p>Email and phone never appear in the query string. They live in {@link LoginChallengeState} so
 * browser history, proxy logs and Referer headers do not retain them.
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
    private final WhatsAppAuthService whatsApp;
    private final GoogleSsoService google;
    private final HostedSignIn hostedSignIn;
    private final SignupService signup;

    @GetMapping("/login")
    public String login(@RequestParam(required = false) String error,
                        @RequestParam(required = false) String signedOut,
                        @RequestParam(required = false) String sent,
                        @RequestParam(required = false) String code,
                        @RequestParam(required = false) String phone,
                        @RequestParam(required = false) String whatsapp,
                        @RequestParam(required = false) String method,
                        @RequestParam(required = false) String clear,
                        // Legacy: accepted once, then stripped so old tabs stop advertising PII.
                        @RequestParam(required = false) String email,
                        @RequestParam(required = false) String number,
                        HttpServletRequest request,
                        Model model) {
        if (clear != null) {
            LoginChallengeState.clear(request);
            return "redirect:/login";
        }

        if ((email != null && !email.isBlank()) || (number != null && !number.isBlank())) {
            if (email != null && !email.isBlank()) {
                LoginChallengeState.setEmail(request, email);
            }
            if (number != null && !number.isBlank()) {
                LoginChallengeState.setPhone(request, number);
            }
            return "redirect:" + cleanLoginLocation(error, signedOut, sent, code, phone, whatsapp, method);
        }

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
        if (sent != null && (phone != null || whatsapp != null)) {
            model.addAttribute("notice", "If that number has an account, a code is on its way.");
        }

        String sessionEmail = LoginChallengeState.email(request);
        String sessionPhone = LoginChallengeState.phone(request);
        boolean identified = !sessionEmail.isBlank();

        // Step flags stay in the query string (reload / back). The address does not.
        model.addAttribute("stage",
                code != null ? "code"
                        : phone != null ? "phone"
                        : whatsapp != null ? "whatsapp"
                        : "choose".equals(method) && identified ? "choose"
                        : "identify");
        model.addAttribute("email", sessionEmail);
        model.addAttribute("number", sessionPhone);
        model.addAttribute("googleClientId", google.enabled() ? google.clientId() : null);
        model.addAttribute("phoneEnabled", phones.enabled());
        model.addAttribute("whatsappEnabled", whatsApp.enabled());
        model.addAttribute("forgotPasswordUrl", properties.urls().console() + "/forgot-password");
        model.addAttribute("signupAvailable", signup.available());
        return "login";
    }

    /**
     * Step one: capture the address into the session, then open step two on a clean URL.
     *
     * <p>POST rather than GET so the address is not written into history as a navigable query.
     */
    @PostMapping("/login/identify")
    public String identify(@RequestParam String email, HttpServletRequest request) {
        LoginChallengeState.setEmail(request, email);
        return "redirect:/login?method=choose";
    }

    /** Sends a link that signs the browser in when opened. */
    @PostMapping("/login/link")
    public String requestLink(@RequestParam(required = false) String email, HttpServletRequest request) {
        String address = resolveEmail(email, request);
        if (address.isBlank()) {
            return "redirect:/login";
        }
        passwordless.requestMagicLink(address, request.getRemoteAddr());
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
    public String requestCode(@RequestParam(required = false) String email, HttpServletRequest request) {
        String address = resolveEmail(email, request);
        if (address.isBlank()) {
            return "redirect:/login";
        }
        passwordless.requestOtp(address, request.getRemoteAddr());
        return "redirect:/login?code";
    }

    @PostMapping("/login/code/verify")
    public String verifyCode(@RequestParam(required = false) String email,
                             @RequestParam String code,
                             HttpServletRequest request,
                             HttpServletResponse response) throws IOException, ServletException {
        String address = resolveEmail(email, request);
        try {
            hostedSignIn.completeAndRedirect(passwordless.authenticateByOtp(address, code),
                    FactorGrantedAuthority.OTT_AUTHORITY, request, response);
            return null;
        } catch (ApiException ex) {
            log.debug("Emailed code rejected: {}", ex.getMessage());
            return "redirect:/login?code&error";
        }
    }

    @PostMapping("/login/phone")
    public String requestPhoneCode(@RequestParam String phone, HttpServletRequest request) {
        try {
            phones.requestOtp(phone, request.getRemoteAddr());
        } catch (ApiException ex) {
            return "redirect:/login?phone&error";
        }
        LoginChallengeState.setPhone(request, phone);
        return "redirect:/login?phone&sent=1";
    }

    @PostMapping("/login/phone/verify")
    public String verifyPhoneCode(@RequestParam(required = false) String phone,
                                  @RequestParam String code,
                                  HttpServletRequest request,
                                  HttpServletResponse response) throws IOException, ServletException {
        String number = resolvePhone(phone, request);
        try {
            hostedSignIn.completeAndRedirect(phones.authenticateByOtp(number, code),
                    FactorGrantedAuthority.OTT_AUTHORITY, request, response);
            return null;
        } catch (ApiException ex) {
            log.debug("SMS code rejected: {}", ex.getMessage());
            return "redirect:/login?phone&error";
        }
    }

    @PostMapping("/login/whatsapp")
    public String requestWhatsAppCode(@RequestParam String phone, HttpServletRequest request) {
        try {
            whatsApp.requestOtp(phone, request.getRemoteAddr());
        } catch (ApiException ex) {
            return "redirect:/login?whatsapp&error";
        }
        LoginChallengeState.setPhone(request, phone);
        return "redirect:/login?whatsapp&sent=1";
    }

    @PostMapping("/login/whatsapp/verify")
    public String verifyWhatsAppCode(@RequestParam(required = false) String phone,
                                     @RequestParam String code,
                                     HttpServletRequest request,
                                     HttpServletResponse response) throws IOException, ServletException {
        String number = resolvePhone(phone, request);
        try {
            hostedSignIn.completeAndRedirect(whatsApp.authenticateByOtp(number, code),
                    FactorGrantedAuthority.OTT_AUTHORITY, request, response);
            return null;
        } catch (ApiException ex) {
            log.debug("WhatsApp code rejected: {}", ex.getMessage());
            return "redirect:/login?whatsapp&error";
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
            hostedSignIn.completeAndRedirect(google.authenticate(credential),
                    FactorGrantedAuthority.AUTHORIZATION_CODE_AUTHORITY, request, response);
            return null;
        } catch (ApiException ex) {
            log.debug("Google credential rejected: {}", ex.getMessage());
            return "redirect:/login?error";
        }
    }

    private static String resolveEmail(String posted, HttpServletRequest request) {
        if (posted != null && !posted.isBlank()) {
            LoginChallengeState.setEmail(request, posted);
            return posted.trim();
        }
        return LoginChallengeState.email(request);
    }

    private static String resolvePhone(String posted, HttpServletRequest request) {
        if (posted != null && !posted.isBlank()) {
            LoginChallengeState.setPhone(request, posted);
            return posted.trim();
        }
        return LoginChallengeState.phone(request);
    }

    private static String cleanLoginLocation(String error,
                                             String signedOut,
                                             String sent,
                                             String code,
                                             String phone,
                                             String whatsapp,
                                             String method) {
        StringBuilder target = new StringBuilder("/login");
        boolean first = true;
        if (error != null) {
            target.append(first ? '?' : '&').append("error");
            if ("expired".equals(error)) {
                target.append("=expired");
            }
            first = false;
        }
        if (signedOut != null) {
            target.append(first ? '?' : '&').append("signedOut");
            first = false;
        }
        if (sent != null) {
            target.append(first ? '?' : '&').append("sent");
            if (!sent.isBlank() && !"1".equals(sent) && !"true".equals(sent)) {
                target.append('=').append(sent);
            } else if ("link".equals(sent)) {
                target.append("=link");
            } else if (!sent.isBlank()) {
                target.append('=').append(sent);
            }
            first = false;
        }
        if (code != null) {
            target.append(first ? '?' : '&').append("code");
            first = false;
        }
        if (phone != null) {
            target.append(first ? '?' : '&').append("phone");
            first = false;
        }
        if (whatsapp != null) {
            target.append(first ? '?' : '&').append("whatsapp");
            first = false;
        }
        if ("choose".equals(method)) {
            target.append(first ? '?' : '&').append("method=choose");
        }
        return target.toString();
    }
}
