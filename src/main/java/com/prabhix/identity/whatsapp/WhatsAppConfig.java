package com.prabhix.identity.whatsapp;

import com.prabhix.identity.config.IdentityProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;

/**
 * Picks the WhatsApp implementation from configuration.
 *
 * <p>Reuses {@code TWILIO_ACCOUNT_SID} / {@code TWILIO_AUTH_TOKEN} from the SMS block — one Twilio
 * account — and gates delivery on {@code TWILIO_WHATSAPP_FROM}. Explicit factory for the same reason
 * as {@link com.prabhix.identity.sms.SmsConfig}.
 */
@Slf4j
@Configuration
public class WhatsAppConfig {

    @Bean
    public WhatsAppSender whatsAppSender(IdentityProperties properties, RestClient.Builder httpBuilder) {
        IdentityProperties.Sms sms = properties.sms();
        IdentityProperties.WhatsApp whatsApp = properties.whatsApp();
        String sid = sms == null ? null : sms.accountSid();

        if (sid == null || sid.isBlank()) {
            log.info("No Twilio account configured, so WhatsApp sign-in is disabled. Set "
                    + "TWILIO_ACCOUNT_SID and TWILIO_WHATSAPP_FROM to enable it.");
            return new DisabledWhatsAppSender();
        }

        if ("mock".equalsIgnoreCase(sid.trim())) {
            log.info("WhatsApp delivery via logging mock (TWILIO_ACCOUNT_SID=mock)");
            return new LoggingWhatsAppSender();
        }

        if (whatsApp == null || whatsApp.fromNumber() == null || whatsApp.fromNumber().isBlank()) {
            // SID may be present for SMS alone. WhatsApp stays off until its own from-number is set.
            log.info("TWILIO_WHATSAPP_FROM is blank, so WhatsApp sign-in is disabled.");
            return new DisabledWhatsAppSender();
        }

        if (sms.authToken() == null || sms.authToken().isBlank()) {
            throw new IllegalStateException(
                    "TWILIO_ACCOUNT_SID is set but TWILIO_AUTH_TOKEN is not");
        }
        return new TwilioWhatsAppSender(properties, httpBuilder);
    }
}
