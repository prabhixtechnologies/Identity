-- Audit trail, plus the two account-lifecycle columns the self-service surface needs.
--
-- Forward-only, and every statement here is safe against a live database: a new table, three
-- nullable columns with no default (a metadata-only change in Postgres), and a CHECK constraint that
-- is added NOT VALID and then validated, so the existing rows are scanned under a lock that does not
-- block writers.

-- One row per thing that happened to an account: a sign-in, a failed one, a password change, a staff
-- action. Written by AuthEventRecorder and read by /internal/admin/events.
--
-- No foreign key to users, deliberately. Events must outlive the account they describe — a deleted
-- user's history is the part of the trail an operator most wants — and an insert here must never fail
-- because a row it names has gone. user_id is also null for failures against addresses that have no
-- account.
--
-- details is free-form jsonb rather than a column per event type. The set of types grows with every
-- flow, and a column each would make every new event a migration.
CREATE TABLE public.auth_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid,
    email public.citext,
    type text NOT NULL,
    outcome text NOT NULL,
    client_id text,
    -- 45 fits a full IPv6 literal, matching device_sessions and auth_challenges.
    ip_address character varying(45),
    user_agent character varying(500),
    -- The staff member behind an ADMIN_* event, from X-Prabhix-Acting-User. Null for anything the
    -- account holder did themselves.
    actor_user_id uuid,
    details jsonb DEFAULT '{}'::jsonb NOT NULL,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT auth_events_pkey PRIMARY KEY (id),
    CONSTRAINT ck_auth_events_outcome CHECK (outcome IN ('SUCCESS', 'FAILURE', 'DENIED'))
);

-- Each index serves one query shape on /internal/admin/events, all of which page newest-first on a
-- keyset of (occurred_at, id).
CREATE INDEX ix_auth_events_user ON public.auth_events USING btree (user_id, occurred_at DESC);
CREATE INDEX ix_auth_events_occurred ON public.auth_events USING btree (occurred_at DESC);
CREATE INDEX ix_auth_events_type ON public.auth_events USING btree (type, occurred_at DESC);

-- Set by POST /api/v1/account/deletion and cleared by DELETE on the same path. Nothing in this
-- service acts on it: the account keeps working so its owner can change their mind, and an operator
-- or a scheduled job completes the deletion after the grace period documented in docs/ACCOUNT.md.
ALTER TABLE public.users ADD COLUMN deletion_requested_at timestamp with time zone;

-- last_used_at is stamped on every successful assertion, so the account page can show which passkey
-- has not been touched in a year. backed_up is the authenticator's BS flag at registration: whether
-- the private key is synced to a cloud keychain, which is the difference between "lose the phone,
-- lose the passkey" and not.
ALTER TABLE public.webauthn_credentials
    ADD COLUMN last_used_at timestamp with time zone,
    ADD COLUMN backed_up boolean;

-- A new challenge purpose for changing the address on an account. The link goes to the NEW address
-- and the challenge's destination is that address, so the existing lookup-by-destination and
-- per-destination cooldown apply unchanged.
ALTER TABLE public.auth_challenges DROP CONSTRAINT ck_auth_challenges_purpose;
ALTER TABLE public.auth_challenges ADD CONSTRAINT ck_auth_challenges_purpose
    CHECK (purpose IN ('MAGIC_LINK', 'EMAIL_OTP', 'SMS_OTP', 'WHATSAPP_OTP', 'PASSWORD_RESET',
                       'EMAIL_VERIFY', 'EMAIL_CHANGE')) NOT VALID;
ALTER TABLE public.auth_challenges VALIDATE CONSTRAINT ck_auth_challenges_purpose;
