package com.prabhix.identity.whatsapp;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;

/**
 * What a deployment with no WhatsApp sender gets.
 *
 * <p>Refuses rather than logging the code and pretending to succeed — same reason as
 * {@link com.prabhix.identity.sms.DisabledSmsSender}.
 */
public class DisabledWhatsAppSender implements WhatsAppSender {

    @Override
    public void send(String e164, String message) {
        throw ApiException.of(ErrorCode.FEATURE_DISABLED,
                "WhatsApp sign-in is not available on this deployment");
    }

    @Override
    public boolean enabled() {
        return false;
    }
}
