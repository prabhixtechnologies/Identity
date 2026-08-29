-- Prabhix Identity: the five tables that answer "who is this".
--
-- Copied from the platform's V1__core_foundation.sql so that an import can be a straight
-- INSERT ... SELECT with no type coercion, with two deliberate differences:
--
--   * users.default_organization_id is gone. An organization is a platform concept, MobiStack has
--     shops instead, and Mailroom has neither. A column here that only one product can populate
--     would put product state in the identity store, which is the thing this service exists to stop.
--   * users.notification_prefs is gone, for the same reason: which product notifies you about what
--     belongs to that product.
--
-- Everything else is byte-compatible, including bcrypt hashes: the cost factor travels inside the
-- hash, so platform's strength-10 and MobiStack's strength-12 both verify here untouched.

CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    version               bigint      NOT NULL DEFAULT 0,
    email                 citext      NOT NULL UNIQUE,
    email_verified_at     timestamptz,
    phone                 varchar(32),
    phone_verified_at     timestamptz,
    -- Nullable: a magic-link or SSO account never has one, and requiring a placeholder would make
    -- "has no password" indistinguishable from "has a password nobody knows".
    password_hash         varchar(120),
    password_changed_at   timestamptz,
    full_name             varchar(160) NOT NULL,
    display_name          varchar(80),
    avatar_url            varchar(500),
    job_title             varchar(120),
    timezone              varchar(64)  NOT NULL DEFAULT 'Asia/Kolkata',
    locale                varchar(16)  NOT NULL DEFAULT 'en-IN',
    status                varchar(24)  NOT NULL DEFAULT 'ACTIVE',
    platform_admin        boolean      NOT NULL DEFAULT false,
    failed_login_attempts integer      NOT NULL DEFAULT 0,
    locked_until          timestamptz,
    last_login_at         timestamptz,
    last_active_at        timestamptz,
    created_at            timestamptz  NOT NULL DEFAULT now(),
    updated_at            timestamptz  NOT NULL DEFAULT now(),
    created_by            uuid,
    updated_by            uuid,
    deleted_at            timestamptz,
    CONSTRAINT ck_users_status CHECK (status IN ('ACTIVE', 'INVITED', 'DISABLED', 'LOCKED')),
    CONSTRAINT ck_users_failed_attempts CHECK (failed_login_attempts >= 0)
);

-- Partial, so a soft-deleted address can be registered again.
CREATE INDEX ix_users_email_active ON users (email) WHERE deleted_at IS NULL;
CREATE INDEX ix_users_status ON users (status) WHERE deleted_at IS NULL;

CREATE TABLE auth_identities (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    version          bigint      NOT NULL DEFAULT 0,
    user_id          uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider         varchar(32) NOT NULL,
    provider_subject varchar(255) NOT NULL,
    provider_email   citext,
    raw_profile      jsonb       NOT NULL DEFAULT '{}',
    linked_at        timestamptz NOT NULL DEFAULT now(),
    last_login_at    timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    created_by       uuid,
    updated_by       uuid,
    CONSTRAINT ck_auth_identities_provider
        CHECK (provider IN ('GOOGLE', 'MICROSOFT', 'GITHUB', 'SAML')),
    -- One Google account is one identity. Without this, a race on first sign-in links the same
    -- provider subject to two users and the second sign-in picks whichever row it finds.
    CONSTRAINT uq_auth_identities_provider_subject UNIQUE (provider, provider_subject)
);

CREATE INDEX ix_auth_identities_user ON auth_identities (user_id);

CREATE TABLE device_sessions (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    version           bigint      NOT NULL DEFAULT 0,
    user_id           uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_id         varchar(128),
    device_name       varchar(160),
    device_type       varchar(24) NOT NULL DEFAULT 'WEB',
    user_agent        varchar(500),
    ip_address        varchar(45),
    last_seen_at      timestamptz NOT NULL DEFAULT now(),
    revoked_at        timestamptz,
    revoked_reason    varchar(64),
    -- SHA-256 of the shared browser session cookie. Does not rotate, so two console hostnames can
    -- exchange it at the same instant; a rotating credential would make the second look like a replay.
    cookie_token_hash varchar(64),
    cookie_expires_at timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    created_by        uuid,
    updated_by        uuid,
    CONSTRAINT ck_device_sessions_type CHECK (device_type IN ('WEB', 'IOS', 'ANDROID', 'API'))
);

-- One live session per device, but revoked rows are kept for the audit trail, hence partial.
CREATE UNIQUE INDEX uq_device_sessions_user_device ON device_sessions (user_id, device_id)
    WHERE device_id IS NOT NULL AND revoked_at IS NULL;
CREATE UNIQUE INDEX uq_device_sessions_cookie ON device_sessions (cookie_token_hash)
    WHERE cookie_token_hash IS NOT NULL;
CREATE INDEX ix_device_sessions_user_active ON device_sessions (user_id) WHERE revoked_at IS NULL;

CREATE TABLE refresh_tokens (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    version     bigint      NOT NULL DEFAULT 0,
    user_id     uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    session_id  uuid        NOT NULL REFERENCES device_sessions (id) ON DELETE CASCADE,
    token_hash  varchar(64) NOT NULL UNIQUE,
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    revoked_at  timestamptz,
    -- The rotation chain. Presenting a token that already has a successor is the replay signal, and
    -- following this pointer is how the whole affected family gets revoked without touching others.
    replaced_by uuid REFERENCES refresh_tokens (id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    created_by  uuid,
    updated_by  uuid
);

CREATE INDEX ix_refresh_tokens_session ON refresh_tokens (session_id);
CREATE INDEX ix_refresh_tokens_expiry ON refresh_tokens (expires_at) WHERE revoked_at IS NULL;

CREATE TABLE auth_challenges (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    version      bigint      NOT NULL DEFAULT 0,
    purpose      varchar(32) NOT NULL,
    -- Nullable: a challenge can be raised for an address before anyone knows whether it belongs to
    -- an account, which is what keeps the response identical either way.
    user_id      uuid REFERENCES users (id) ON DELETE CASCADE,
    destination  citext      NOT NULL,
    secret_hash  varchar(64) NOT NULL,
    expires_at   timestamptz NOT NULL,
    consumed_at  timestamptz,
    attempts     integer     NOT NULL DEFAULT 0,
    max_attempts integer     NOT NULL DEFAULT 5,
    ip_address   varchar(45),
    metadata     jsonb       NOT NULL DEFAULT '{}',
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    created_by   uuid,
    updated_by   uuid,
    CONSTRAINT ck_auth_challenges_purpose CHECK (purpose IN
        ('MAGIC_LINK', 'EMAIL_OTP', 'SMS_OTP', 'WHATSAPP_OTP', 'PASSWORD_RESET', 'EMAIL_VERIFY')),
    CONSTRAINT ck_auth_challenges_attempts CHECK (attempts >= 0 AND max_attempts > 0)
);

CREATE INDEX ix_auth_challenges_lookup ON auth_challenges (secret_hash, purpose)
    WHERE consumed_at IS NULL;
CREATE INDEX ix_auth_challenges_destination ON auth_challenges (destination, purpose, created_at DESC)
    WHERE consumed_at IS NULL;
