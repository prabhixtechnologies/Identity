package com.prabhix.identity.sms;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
/**
 * What a deployment with no SMS provider gets.
 *
 * <p>Refuses rather than logging the code and pretending to succeed. A no-op that returns quietly is
 * the shape of bug that reaches production: the endpoint answers 200, the phone never rings, and the
 * report is "OTP login is broken" with nothing in the logs to disagree with. Refusing means the
 * feature is visibly absent instead of invisibly broken.
 */
public class DisabledSmsSender implements SmsSender {

    @Override
    public void send(String e164, String message) {
        throw ApiException.of(ErrorCode.FEATURE_DISABLED,
                "Phone sign-in is not available on this deployment");
    }

    @Override
    public boolean enabled() {
        return false;
    }
}
