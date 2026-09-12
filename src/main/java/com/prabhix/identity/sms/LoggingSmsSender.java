package com.prabhix.identity.sms;

import lombok.extern.slf4j.Slf4j;

/**
 * Local stand-in that writes the OTP to the application log instead of paying a carrier.
 *
 * <p>Selected when {@code TWILIO_ACCOUNT_SID=mock}. Enabled on purpose: the phone flows must be
 * exercisable without Twilio or Mailpit, and an INFO line with the code is the whole point of the
 * mock — a disabled sender would hide the feature the same way a missing SID does.
 */
@Slf4j
public class LoggingSmsSender implements SmsSender {

    @Override
    public void send(String e164, String message) {
        // Destination is included so a developer can tell two concurrent sign-ins apart. The message
        // itself carries the OTP; that is intentional for local mock only.
        log.info("SMS mock → {}: {}", e164, message);
    }

    @Override
    public boolean enabled() {
        return true;
    }
}
