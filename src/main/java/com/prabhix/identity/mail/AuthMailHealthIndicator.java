package com.prabhix.identity.mail;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.stereotype.Component;

/**
 * Reports whether a magic link would actually be delivered.
 *
 * <p>This is the indicator {@code application.yml} promises when it disables Spring Boot's own
 * {@code MailHealthIndicator}. That one opens a socket to {@code spring.mail.host} on every check
 * regardless of how mail is really sent, so on a service that sends through an API it reported the
 * whole application DOWN — which is what it did on Identity's first boot in production, and what the
 * platform backend had already had to disable for the same reason.
 *
 * <p>Asking the transport instead means the check follows the transport actually in use, and on SES
 * it distinguishes the states that decide the outcome: no credentials, an account not allowed to
 * send, a from-address that is not a verified identity.
 *
 * <p>Not in the readiness group, which lists only {@code readinessState} and {@code redis}. Being
 * unable to send mail must not take Identity out of service: token issuance, refresh and JWKS do not
 * need mail, and pulling the instance would turn a mail outage into a sign-in outage for everyone
 * already holding a session. It does show in the aggregate {@code /actuator/health}, which is the
 * signal to act on.
 */
@Component
@RequiredArgsConstructor
public class AuthMailHealthIndicator implements HealthIndicator {

    private final AuthMailTransport transport;

    @Override
    public Health health() {
        AuthMailTransport.Status status = transport.status();
        Health.Builder health = status.usable() ? Health.up() : Health.down();
        health.withDetail("transport", transport.id());
        if (status.note() != null) {
            health.withDetail("note", status.note());
        }
        return health.build();
    }
}
