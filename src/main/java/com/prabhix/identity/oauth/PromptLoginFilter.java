package com.prabhix.identity.oauth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * {@code prompt=login} has to show the login page, not mint another code from the session that is
 * already there.
 *
 * <p>A staff cookie exchange that sees a new network sends the browser back through authorize with
 * that prompt. The session opened by the previous sign-in is still authenticated, and the
 * authorization endpoint will issue a code for it. The product then lands on its callback, exchanges
 * the same unchanged cookie, and is sent here again. Stripping the prompt before the request is
 * saved means the sign-in that follows resumes a normal authorize instead of demanding login once more.
 */
final class PromptLoginFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (!isAuthorize(request) || !promptContainsLogin(request.getParameter("prompt"))) {
            filterChain.doFilter(request, response);
            return;
        }
        SecurityContextHolder.clearContext();
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        }
        filterChain.doFilter(new LoginPromptRemoved(request), response);
    }

    private static boolean isAuthorize(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return uri != null && uri.endsWith("/oauth2/authorize");
    }

    private static boolean promptContainsLogin(String prompt) {
        if (prompt == null || prompt.isBlank()) {
            return false;
        }
        for (String value : prompt.split("\\s+")) {
            if ("login".equals(value)) {
                return true;
            }
        }
        return false;
    }

    /**
     * The authorization request as saved for after sign-in, without the instruction to sign in again.
     */
    private static final class LoginPromptRemoved extends HttpServletRequestWrapper {

        private LoginPromptRemoved(HttpServletRequest request) {
            super(request);
        }

        @Override
        public String getParameter(String name) {
            if ("max_age".equals(name)) {
                return null;
            }
            if ("prompt".equals(name)) {
                return promptWithoutLogin(super.getParameter(name));
            }
            return super.getParameter(name);
        }

        @Override
        public String[] getParameterValues(String name) {
            String value = getParameter(name);
            return value == null ? null : new String[] {value};
        }

        @Override
        public Map<String, String[]> getParameterMap() {
            Map<String, String[]> map = new LinkedHashMap<>(super.getParameterMap());
            map.remove("max_age");
            String prompt = promptWithoutLogin(first(map.get("prompt")));
            if (prompt == null) {
                map.remove("prompt");
            } else {
                map.put("prompt", new String[] {prompt});
            }
            return map;
        }

        @Override
        public String getQueryString() {
            String raw = super.getQueryString();
            if (raw == null || raw.isBlank()) {
                return raw;
            }
            String kept = Arrays.stream(raw.split("&"))
                    .filter(part -> !part.startsWith("max_age=") && !part.equals("max_age"))
                    .map(LoginPromptRemoved::withoutLoginPrompt)
                    .filter(part -> part != null && !part.isEmpty())
                    .collect(Collectors.joining("&"));
            return kept.isEmpty() ? null : kept;
        }

        private static String withoutLoginPrompt(String part) {
            if (!part.startsWith("prompt=")) {
                return part;
            }
            String prompt = promptWithoutLogin(part.substring("prompt=".length()));
            return prompt == null ? null : "prompt=" + prompt;
        }

        private static String promptWithoutLogin(String prompt) {
            if (prompt == null || prompt.isBlank()) {
                return null;
            }
            String kept = Arrays.stream(prompt.split("\\s+"))
                    .filter(value -> !value.isEmpty() && !"login".equals(value))
                    .collect(Collectors.joining(" "));
            return kept.isEmpty() ? null : kept;
        }

        private static String first(String[] values) {
            return values == null || values.length == 0 ? null : values[0];
        }
    }
}
