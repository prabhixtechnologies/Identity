package com.prabhix.identity.oauth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

/**
 * Holds the address / phone the person is proving on the hosted login page.
 *
 * <p>Kept in the HTTP session rather than the query string. Putting an email or phone in
 * {@code /login?email=} leaks PII into browser history, proxy logs, analytics Referers, and
 * screenshots — fine for a demo, not for a shared enterprise identity provider.
 *
 * <p>Step flags ({@code method=choose}, {@code code}, {@code phone}) can stay in the URL: they are
 * not identifying. Reload and back still work because the session outlives the redirect.
 */
public final class LoginChallengeState {

    private static final String EMAIL = "prabhix.login.email";
    private static final String PHONE = "prabhix.login.phone";

    private LoginChallengeState() {}

    public static void setEmail(HttpServletRequest request, String email) {
        HttpSession session = request.getSession(true);
        if (email == null || email.isBlank()) {
            session.removeAttribute(EMAIL);
        } else {
            session.setAttribute(EMAIL, email.trim());
        }
    }

    public static String email(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return "";
        }
        Object value = session.getAttribute(EMAIL);
        return value instanceof String s ? s : "";
    }

    public static void setPhone(HttpServletRequest request, String phone) {
        HttpSession session = request.getSession(true);
        if (phone == null || phone.isBlank()) {
            session.removeAttribute(PHONE);
        } else {
            session.setAttribute(PHONE, phone.trim());
        }
    }

    public static String phone(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return "";
        }
        Object value = session.getAttribute(PHONE);
        return value instanceof String s ? s : "";
    }

    /** “Change” on step two: forget who we thought they were. */
    public static void clear(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return;
        }
        session.removeAttribute(EMAIL);
        session.removeAttribute(PHONE);
    }
}
