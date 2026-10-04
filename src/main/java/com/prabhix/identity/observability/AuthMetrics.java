package com.prabhix.identity.observability;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Component;

/** Counters for the session and step-up behaviour operators need to see. */
@Component
public class AuthMetrics {

    private final Counter sessionExtended;
    private final Counter stepUpRequired;
    private final Counter cookieGrace;
    private final Counter newDevice;

    public AuthMetrics(MeterRegistry meters) {
        this.sessionExtended = counter(meters, "prabhix.identity.session.extended",
                "Browser session slid forward by activity");
        this.stepUpRequired = counter(meters, "prabhix.identity.step_up.required",
                "A sign-in or renewal asked for a fresh proof");
        this.cookieGrace = counter(meters, "prabhix.identity.cookie.grace_used",
                "A previous browser cookie was accepted inside the rotation grace window");
        this.newDevice = counter(meters, "prabhix.identity.risk.new_device",
                "A sign-in opened a device this account had not used");
    }

    public void sessionExtended() {
        sessionExtended.increment();
    }

    public void stepUpRequired() {
        stepUpRequired.increment();
    }

    public void cookieGrace() {
        cookieGrace.increment();
    }

    public void newDevice() {
        newDevice.increment();
    }

    private static Counter counter(MeterRegistry meters, String name, String description) {
        return Counter.builder(name).description(description).register(meters);
    }
}
