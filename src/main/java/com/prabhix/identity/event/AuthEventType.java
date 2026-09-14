package com.prabhix.identity.event;

/**
 * Everything that gets written to {@code auth_events}.
 *
 * <p>Stored as text, not as an enum type in Postgres, so adding a value here is a code change and not
 * a migration. The names are public: {@code /internal/admin/events?type=} filters on them and the
 * admin console shows them, so renaming one is a contract change.
 */
public enum AuthEventType {
    LOGIN_SUCCEEDED,
    LOGIN_FAILED,
    LOGOUT,
    LOCKED_OUT,
    PASSWORD_CHANGED,
    PASSWORD_RESET_REQUESTED,
    PASSWORD_RESET_COMPLETED,
    PASSWORD_SET,
    EMAIL_CHANGE_REQUESTED,
    EMAIL_CHANGED,
    PASSKEY_REGISTERED,
    PASSKEY_REMOVED,
    PASSKEY_RENAMED,
    GOOGLE_LINKED,
    GOOGLE_UNLINKED,
    SESSION_REVOKED,
    ALL_SESSIONS_REVOKED,
    PROFILE_UPDATED,
    DELETION_REQUESTED,
    DELETION_CANCELLED,
    ADMIN_USER_DISABLED,
    ADMIN_USER_ENABLED,
    ADMIN_USER_UNLOCKED,
    ADMIN_FORCE_RESET,
    ADMIN_SESSIONS_REVOKED,
    TOKENS_REVOKED;

    /**
     * @param outcome how it went. {@code DENIED} is for a request that was well-formed and refused on
     *     policy — a disabled account, a locked one, the last credential — as opposed to a
     *     {@code FAILURE}, which is a wrong password or an expired link.
     */
    public enum Outcome {
        SUCCESS, FAILURE, DENIED
    }
}
