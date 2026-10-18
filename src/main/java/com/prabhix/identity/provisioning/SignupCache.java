package com.prabhix.identity.provisioning;

import java.time.Duration;

/** The short-lived store that holds a signup until the emailed code is entered. */
interface SignupCache {

    void put(String key, String value, Duration ttl);

    /** Null when the key is missing or its time has run out. */
    String get(String key);

    /** Seconds until the key expires. Zero or less means it is already gone. */
    long secondsLeft(String key);

    void delete(String... keys);
}
