package com.prabhix.identity.sms;

/**
 * Sends one short message.
 *
 * <p>An interface with two implementations rather than a direct call to a provider, because the
 * provider is the part most likely to change: SMS to Indian numbers needs DLT registration, and which
 * aggregator that goes through is a commercial decision, not an architectural one. Swapping Twilio for
 * MSG91 or SNS should be one new class and a config value.
 */
public interface SmsSender {

    /**
     * @param e164 destination in E.164 form, e.g. {@code +919876543210}
     * @throws com.prabhix.identity.common.ApiException if the message could not be handed to the
     *     provider. Never silent: an OTP the person is waiting for and will never receive is worse
     *     than being told immediately that it could not be sent.
     */
    void send(String e164, String message);

    /** Whether this deployment can actually deliver. False makes the phone flows refuse up front. */
    boolean enabled();
}
