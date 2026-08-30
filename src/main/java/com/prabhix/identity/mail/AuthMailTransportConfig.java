package com.prabhix.identity.mail;

import com.prabhix.identity.config.IdentityProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;

/**
 * Chooses the one transport that carries account-access mail.
 *
 * <p>Built here rather than having both transports be components, so that running on SES does not
 * also require an SMTP host to exist, and so the choice is made once at startup and logged. Which
 * way sign-in mail leaves is worth being able to read out of the logs of a running service.
 *
 * <p>A misconfiguration fails the context instead of falling back. Falling back would mean a service
 * that starts cleanly and sends nothing, and the only symptom is users who cannot sign in — the
 * failure mode that is hardest to attribute and most expensive to leave running.
 */
@Slf4j
@Configuration
public class AuthMailTransportConfig {

    @Bean
    AuthMailTransport authMailTransport(IdentityProperties properties,
                                        ObjectProvider<JavaMailSender> mailSenders,
                                        @Value("${spring.mail.host:}") String smtpHost) {
        IdentityProperties.Mail mail = properties.mail();
        boolean ses = switch (mail.transport()) {
            case SES -> true;
            case SMTP -> false;
            // Region is the only setting SES needs when credentials come from the instance role, so
            // it is the one signal that distinguishes a deployment on AWS from a laptop.
            case AUTO -> mail.ses().configured();
        };

        if (ses) {
            if (!mail.ses().configured()) {
                throw new IllegalStateException("prabhix.identity.mail.transport is SES but no SES "
                        + "region is configured; set SES_REGION");
            }
            log.info("Auth mail goes through SES in {} as {} (credentials: {})",
                    mail.ses().region(), mail.from(),
                    mail.ses().hasStaticCredentials() ? "static access key" : "default provider chain");
            return new SesAuthMailTransport(mail);
        }

        JavaMailSender sender = mailSenders.getIfAvailable();
        if (sender == null) {
            throw new IllegalStateException("auth mail would go over SMTP but no mail sender is "
                    + "configured; set SMTP_HOST or select the SES transport");
        }
        // Worth a warning and not just an info line: this is the setting a production box would have
        // if SES_REGION went missing, and localhost:587 accepts nothing.
        if ("localhost".equals(smtpHost) || "127.0.0.1".equals(smtpHost)) {
            log.warn("Auth mail goes over SMTP to {}, which is only right if a relay runs alongside "
                    + "this service. Nothing will be delivered otherwise.", smtpHost);
        } else {
            log.info("Auth mail goes over SMTP to {} as {}", smtpHost, mail.from());
        }
        return new SmtpAuthMailTransport(sender, smtpHost);
    }
}
