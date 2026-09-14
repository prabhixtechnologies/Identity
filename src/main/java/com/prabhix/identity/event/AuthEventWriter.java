package com.prabhix.identity.event;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * The one method that touches the table, in a transaction of its own.
 *
 * <p>A separate bean rather than a private method on {@link AuthEventRecorder}, because the
 * transaction attribute only applies through the proxy. {@code REQUIRES_NEW} is what makes a failed
 * sign-in leave a row behind: the flow that records it is about to throw, and the transaction it runs
 * in is about to roll back, taking anything written inside it along.
 */
@Component
@RequiredArgsConstructor
class AuthEventWriter {

    private final AuthEventRepository events;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void write(AuthEventRecord record) {
        events.save(record);
    }
}
