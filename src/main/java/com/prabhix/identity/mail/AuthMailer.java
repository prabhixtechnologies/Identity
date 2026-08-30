package com.prabhix.identity.mail;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.config.IdentityProperties;
import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

/**
 * Sends the four emails that gate account access: magic link, OTP, password reset, email verification.
 *
 * <p>Sent from here rather than handed to the platform's mail subsystem. Calling the platform would
 * make identity depend on a product that is meant to sit on top of it, and identity has to work
 * before any product does. {@link AuthMailTransport} is the dependency instead — SES in production,
 * SMTP in development — and these four messages are short enough that a template engine would cost
 * more than it saves.
 *
 * <p><b>Failures are thrown, never swallowed.</b> The platform once reported success for mail it had
 * only written to a log, and marked it {@code SENT}; a magic link that is silently dropped is the
 * same bug with the user locked out at the end of it. If the message cannot be handed to a relay, the
 * request fails and the caller is told to try again.
 */
@Slf4j
@Component
public class AuthMailer {

    private final AuthMailTransport transport;
    private final String fromAddress;
    private final String fromName;

    public AuthMailer(AuthMailTransport transport, IdentityProperties properties) {
        this.transport = transport;
        this.fromAddress = properties.mail().from();
        this.fromName = properties.mail().fromName();
    }

    public void sendMagicLink(String to, String name, String link, long expiryMinutes) {
        send(to, "Your sign-in link", body(
                "Hello " + escape(name) + ",",
                "Use the button below to sign in. The link works once and expires in "
                        + expiryMinutes + " minutes.",
                button(link, "Sign in"),
                "If you did not ask for this, you can ignore this email — nobody can sign in without it."));
    }

    public void sendOtp(String to, String code, long expiryMinutes) {
        send(to, "Your sign-in code: " + code, body(
                "Hello,",
                "Your sign-in code is below. It expires in " + expiryMinutes + " minutes.",
                "<p style=\"font-size:32px;letter-spacing:8px;font-weight:600;margin:24px 0\">"
                        + escape(code) + "</p>",
                "If you did not ask for this, somebody may have your password. Change it."));
    }

    public void sendPasswordReset(String to, String name, String link, long expiryMinutes) {
        send(to, "Reset your password", body(
                "Hello " + escape(name) + ",",
                "Use the button below to choose a new password. The link works once and expires in "
                        + expiryMinutes + " minutes.",
                button(link, "Choose a new password"),
                "If you did not ask for this, you can ignore this email. Your password is unchanged."));
    }

    public void sendEmailVerification(String to, String name, String link, long expiryMinutes) {
        send(to, "Confirm your email address", body(
                "Hello " + escape(name) + ",",
                "Confirm this address so we can reach you about your account. The link expires in "
                        + expiryMinutes + " minutes.",
                button(link, "Confirm my email"),
                "If you did not create an account, you can ignore this email."));
    }

    private void send(String to, String subject, String html) {
        try {
            MimeMessage message = transport.createMessage();
            MimeMessageHelper helper =
                    new MimeMessageHelper(message, false, StandardCharsets.UTF_8.name());
            helper.setFrom(fromAddress, fromName);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(html, true);
            transport.send(message);
        } catch (AuthMailUndeliverable | jakarta.mail.MessagingException
                 | java.io.UnsupportedEncodingException ex) {
            // The address is not logged. This runs for addresses that may not have an account, and
            // a log line proving one exists is the enumeration leak the generic response prevents.
            log.error("Could not send the {} email over {}", subject, transport.id(), ex);
            throw ApiException.of(ErrorCode.DEPENDENCY_UNAVAILABLE,
                    "We could not send that email just now. Please try again in a moment.");
        }
    }

    private String button(String link, String label) {
        String safe = escape(link);
        return "<p style=\"margin:24px 0\">"
                + "<a href=\"" + safe + "\" style=\"background:#4f46e5;color:#fff;padding:12px 20px;"
                + "border-radius:8px;text-decoration:none;font-weight:600\">" + escape(label) + "</a>"
                + "</p><p style=\"font-size:13px;color:#6b7280\">"
                + "If the button does not work, paste this into your browser:<br>" + safe + "</p>";
    }

    private String body(String... paragraphs) {
        StringBuilder html = new StringBuilder(
                "<div style=\"font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;"
                        + "font-size:15px;line-height:1.6;color:#111827;max-width:520px\">");
        for (String paragraph : paragraphs) {
            html.append(paragraph.startsWith("<") ? paragraph : "<p>" + paragraph + "</p>");
        }
        return html.append("<p style=\"font-size:13px;color:#6b7280;margin-top:32px\">")
                .append("Prabhix Technologies</p></div>")
                .toString();
    }

    /**
     * The name and the link both reach this from user-controlled data — a display name someone chose,
     * and a console URL assembled from configuration — so neither goes into HTML unescaped.
     */
    private String escape(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }
}
