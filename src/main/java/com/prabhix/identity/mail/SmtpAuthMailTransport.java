package com.prabhix.identity.mail;

import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;

/**
 * SMTP submission, through whatever {@code spring.mail.*} points at — Mailpit in development, a
 * relay or the self-hosted mail server elsewhere.
 *
 * <p>Not a {@code @Component}: {@link AuthMailTransportConfig} builds whichever transport is
 * selected, so that choosing SES does not also require an SMTP host to exist.
 */
@RequiredArgsConstructor
public class SmtpAuthMailTransport implements AuthMailTransport {

    private final JavaMailSender sender;
    private final String host;

    @Override
    public String id() {
        return "SMTP";
    }

    @Override
    public MimeMessage createMessage() {
        return sender.createMimeMessage();
    }

    @Override
    public void send(MimeMessage message) {
        try {
            sender.send(message);
        } catch (MailException ex) {
            throw new AuthMailUndeliverable("SMTP relay " + host + " rejected the message", ex);
        }
    }

    /**
     * Reports usable without dialling the relay.
     *
     * <p>Opening a connection on every health check is what made Spring Boot's own mail indicator
     * unusable here — see {@code application.yml} — and an SMTP relay's answer to a connection
     * attempt says nothing about whether it will accept the next message anyway. A send that fails
     * fails loudly and the request reports it, which is where an SMTP problem is actually visible.
     */
    @Override
    public Status status() {
        return Status.usable("SMTP submission to " + host + " (not probed)");
    }
}
