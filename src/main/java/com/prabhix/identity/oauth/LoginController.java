package com.prabhix.identity.oauth;

import com.prabhix.identity.config.IdentityProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/** Renders the hosted sign-in page. The form posts back to {@code /login}, handled by Spring Security. */
@Controller
@RequiredArgsConstructor
public class LoginController {

    private final IdentityProperties properties;

    @GetMapping("/login")
    public String login(@RequestParam(required = false) String error,
                        @RequestParam(required = false) String signedOut,
                        Model model) {
        // One message for every failure. Distinguishing "no such account" from "wrong password" here
        // would let anyone enumerate which addresses have accounts, one guess at a time.
        if (error != null) {
            model.addAttribute("error", "Those details do not match an account.");
        }
        if (signedOut != null) {
            model.addAttribute("notice", "You have been signed out.");
        }
        model.addAttribute("forgotPasswordUrl",
                properties.urls().console() + "/forgot-password");
        return "login";
    }
}
