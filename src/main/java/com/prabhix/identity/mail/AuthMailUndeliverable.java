package com.prabhix.identity.mail;

/**
 * A message could not be handed to a relay.
 *
 * <p>Unchecked, and deliberately not caught anywhere except {@link AuthMailer}, which turns it into
 * a response telling the caller to try again. The one thing that must never happen is for this to be
 * swallowed: every message this service sends is the only way a user can get into their account.
 */
public class AuthMailUndeliverable extends RuntimeException {

    public AuthMailUndeliverable(String message, Throwable cause) {
        super(message, cause);
    }

    public AuthMailUndeliverable(String message) {
        super(message);
    }
}
