package com.prabhix.identity.sms;

import com.prabhix.identity.config.IdentityProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;

/**
 * Picks the SMS implementation from configuration.
 *
 * <p>An explicit factory rather than {@code @ConditionalOnMissingBean} on two scanned components.
 * That annotation is evaluated against beans registered so far, and component scanning does not
 * promise an order — so it works until the day it does not, and the failure is a context that starts
 * with the wrong sender rather than one that refuses to start.
 */
@Slf4j
@Configuration
public class SmsConfig {

    @Bean
    public SmsSender smsSender(IdentityProperties properties, RestClient.Builder httpBuilder) {
        IdentityProperties.Sms sms = properties.sms();
        if (sms == null || sms.accountSid() == null || sms.accountSid().isBlank()) {
            log.info("No SMS provider configured, so phone sign-in is disabled. Set "
                    + "TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN and TWILIO_FROM_NUMBER to enable it.");
            return new DisabledSmsSender();
        }
        if (sms.authToken() == null || sms.authToken().isBlank()) {
            // Refused at startup rather than at the first sign-in attempt. Half-configured credentials
            // would authenticate as nobody and return 401 from Twilio, which reads as their outage.
            throw new IllegalStateException(
                    "TWILIO_ACCOUNT_SID is set but TWILIO_AUTH_TOKEN is not");
        }
        boolean hasSender = (sms.fromNumber() != null && !sms.fromNumber().isBlank())
                || (sms.messagingServiceSid() != null && !sms.messagingServiceSid().isBlank());
        if (!hasSender) {
            throw new IllegalStateException("Twilio needs either TWILIO_FROM_NUMBER or "
                    + "TWILIO_MESSAGING_SERVICE_SID. For Indian numbers the messaging service is the "
                    + "one that carries the DLT template registration.");
        }
        return new TwilioSmsSender(properties, httpBuilder);
    }
}
