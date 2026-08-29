package com.prabhix.identity.sms;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.config.IdentityProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

/**
 * Delivery through Twilio's REST API.
 *
 * <p>Called directly rather than through Twilio's SDK: this is one form POST with basic auth, and the
 * SDK would add a transitive dependency tree to a service whose whole point is a small attack surface.
 *
 * <p>Constructed by {@link SmsConfig} only when an account SID is configured. A deployment without
 * one gets {@link DisabledSmsSender} instead.
 */
@Slf4j
public class TwilioSmsSender implements SmsSender {

    private final IdentityProperties.Sms config;
    private final RestClient http;

    public TwilioSmsSender(IdentityProperties properties, RestClient.Builder httpBuilder) {
        this.config = properties.sms();
        this.http = httpBuilder
                .baseUrl("https://api.twilio.com/2010-04-01/Accounts/" + config.accountSid())
                .defaultHeaders(headers ->
                        headers.setBasicAuth(config.accountSid(), config.authToken()))
                .build();
        log.info("SMS delivery via Twilio, from {}", config.fromNumber());
    }

    @Override
    public void send(String e164, String message) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("To", e164);
        form.add("Body", message);
        // A messaging service handles sender-id selection and DLT templates for India; a bare from
        // number does not. Either works, so both are accepted and whichever is configured is used.
        if (config.messagingServiceSid() != null && !config.messagingServiceSid().isBlank()) {
            form.add("MessagingServiceSid", config.messagingServiceSid());
        } else {
            form.add("From", config.fromNumber());
        }

        try {
            http.post()
                    .uri("/Messages.json")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .toBodilessEntity();
        } catch (RuntimeException ex) {
            // The number is deliberately absent from the log. An OTP destination in a log line is a
            // phone number in every downstream log sink, which is more of it than anyone needs.
            log.error("Twilio rejected an SMS: {}", ex.getMessage());
            throw ApiException.of(ErrorCode.INTERNAL_ERROR,
                    "Could not send the code. Try again in a moment.");
        }
    }

    @Override
    public boolean enabled() {
        return true;
    }
}
