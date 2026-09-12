package com.prabhix.identity.whatsapp;

import lombok.extern.slf4j.Slf4j;

/**
 * Local stand-in that writes the OTP to the application log.
 *
 * <p>Selected when {@code TWILIO_ACCOUNT_SID=mock}, matching {@link
 * com.prabhix.identity.sms.LoggingSmsSender}, so both channels are exercisable without Twilio.
 */
@Slf4j
public class LoggingWhatsAppSender implements WhatsAppSender {

    @Override
    public void send(String e164, String message) {
        log.info("WhatsApp mock → {}: {}", e164, message);
    }

    @Override
    public boolean enabled() {
        return true;
    }
}
