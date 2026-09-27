package com.prabhix.identity.oauth;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.security.web.csrf.MissingCsrfTokenException;

/** Detects CSRF failures on hosted logout POSTs that should show the confirmation page instead. */
final class LogoutCsrfRedirect {

    private LogoutCsrfRedirect() {
    }

    static boolean shouldShowConfirmationPage(HttpServletRequest request, Exception denied) {
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            return false;
        }
        String path = request.getRequestURI();
        if (path == null || !"/logout".equals(path)) {
            return false;
        }
        return denied instanceof MissingCsrfTokenException || denied instanceof InvalidCsrfTokenException;
    }
}
