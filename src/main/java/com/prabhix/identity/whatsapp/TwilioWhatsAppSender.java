package com.prabhix.identity.whatsapp;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.config.IdentityProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

/**
 * Delivery through Twilio's Messages API with WhatsApp addressing.
 *
 * <p>Same form POST as SMS, but {@code From} and {@code To} must carry the {@code whatsapp:} scheme
 * prefix. Constructed by {@link WhatsAppConfig} only when an account SID and WhatsApp from-number are
 * configured.
 */
@Slf4j
public class TwilioWhatsAppSender implements WhatsAppSender {

    private final IdentityProperties.Sms sms;
    private final String from;
    private final RestClient http;

    public TwilioWhatsAppSender(IdentityProperties properties, RestClient.Builder httpBuilder) {
        this.sms = properties.sms();
        this.from = whatsappAddress(properties.whatsApp().fromNumber());
        this.http = httpBuilder
                .baseUrl("https://api.twilio.com/2010-04-01/Accounts/" + sms.accountSid())
                .defaultHeaders(headers ->
                        headers.setBasicAuth(sms.accountSid(), sms.authToken()))
                .build();
        log.info("WhatsApp delivery via Twilio, from {}", from);
    }

    @Override
    public void send(String e164, String message) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("From", from);
        form.add("To", whatsappAddress(e164));
        form.add("Body", message);

        try {
            http.post()
                    .uri("/Messages.json")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .toBodilessEntity();
        } catch (RuntimeException ex) {
            log.error("Twilio rejected a WhatsApp message: {}", ex.getMessage());
            throw ApiException.of(ErrorCode.INTERNAL_ERROR,
                    "Could not send the code. Try again in a moment.");
        }
    }

    @Override
    public boolean enabled() {
        return true;
    }

    /** Twilio requires the scheme prefix; compose may already include it or only the E.164. */
    static String whatsappAddress(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        if (trimmed.regionMatches(true, 0, "whatsapp:", 0, "whatsapp:".length())) {
            return "whatsapp:" + trimmed.substring("whatsapp:".length());
        }
        return "whatsapp:" + trimmed;
    }
}
