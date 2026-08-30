package com.prabhix.identity.mail;

import jakarta.mail.internet.MimeMessage;

/**
 * How an account-access email leaves this service.
 *
 * <p>Identity sends its own mail rather than calling the platform's mail subsystem, because the
 * platform is a product that sits on top of identity and identity has to work before any product
 * does. That leaves the choice of transport here, and there are two worth having: SMTP submission,
 * which reaches Mailpit in development and a self-hosted relay if we ever run one, and the SES API,
 * which is what production uses.
 *
 * <p>The message is built by the caller and handed over already assembled, so both transports send
 * byte-identical MIME. SES is given the raw message rather than its structured content API for the
 * same reason: one message builder, one set of headers, no second rendering path that only
 * production exercises.
 */
public interface AuthMailTransport {

    /** Short name for logs and the health endpoint, e.g. {@code SES}. */
    String id();

    /**
     * An empty message this transport can send. SMTP needs one built from the {@code Session} it was
     * configured with, so the caller cannot construct it itself.
     */
    MimeMessage createMessage();

    /**
     * Hands the message to the relay.
     *
     * @throws AuthMailUndeliverable if it was not accepted. Never returns normally without having
     *     handed the message over: the platform once logged mail it had not sent and recorded it as
     *     {@code SENT}, and the same bug here locks a user out of their account.
     */
    void send(MimeMessage message);

    /** Whether a send would be accepted right now, without sending anything. */
    Status status();

    /**
     * @param usable false only when delivery is known to fail — not when it merely cannot be
     *     confirmed. A send-only IAM policy cannot read its own account status, and reporting that
     *     as broken would take mail down for being correctly least-privileged.
     * @param note a caveat worth surfacing even when usable, or null. An SES account still in the
     *     sandbox delivers only to verified recipients, which is indistinguishable from mail
     *     vanishing unless somebody says so out loud.
     */
    record Status(boolean usable, String note) {

        public static Status usable(String note) {
            return new Status(true, note);
        }

        public static Status unusable(String note) {
            return new Status(false, note);
        }
    }
}
