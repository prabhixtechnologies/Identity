package com.prabhix.identity.whatsapp;

/**
 * Sends one WhatsApp message, for OTP sign-in.
 *
 * <p>Separate from {@link com.prabhix.identity.sms.SmsSender} because the transport, sender id and
 * template rules differ even when both ride Twilio — and a deployment may enable one without the
 * other (sandbox WhatsApp from-number without a production SMS messaging service, or the reverse).
 */
public interface WhatsAppSender {

    /**
     * @param e164 destination in E.164 form, e.g. {@code +919876543210}
     * @throws com.prabhix.identity.common.ApiException if the message could not be handed to the
     *     provider. Never silent: an OTP the person is waiting for and will never receive is worse
     *     than being told immediately that it could not be sent.
     */
    void send(String e164, String message);

    /** Whether this deployment can actually deliver. False makes the WhatsApp flows refuse up front. */
    boolean enabled();
}
