package com.prabhix.identity.risk;

import org.springframework.stereotype.Component;

/**
 * Built-in risk rules. No external scorer.
 *
 * <p>A network change on a staff session asks for a fresh passkey or one-time code. The same change
 * for everyone else is recorded and allowed: mobile networks renumber too often to make that a
 * sign-out.
 */
@Component
public class RiskEvaluator {

    /**
     * A device this account has not used before. The sign-in that opened it is the proof, so the
     * session is allowed. Callers still record it: that record is how a new laptop shows up later.
     */
    public Decision newDevice() {
        return Decision.ALLOW;
    }

    public Decision networkChange(boolean staff, String previousIp, String currentIp) {
        if (previousIp == null || previousIp.isBlank()
                || currentIp == null || currentIp.isBlank()
                || previousIp.equals(currentIp)) {
            return Decision.ALLOW;
        }
        return staff ? Decision.STEP_UP : Decision.ALLOW;
    }

    public enum Decision {
        ALLOW, STEP_UP
    }
}
