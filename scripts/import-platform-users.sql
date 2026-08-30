-- Seeds the identity database from the platform's users table.
--
-- Run once, before the gateway is pointed at this service. Reruns are safe: every insert is
-- ON CONFLICT DO NOTHING keyed on the same primary keys, so a second run adds only what a first run
-- missed and never overwrites what identity has since changed.
--
-- Ids are preserved deliberately. The platform's twenty-one foreign keys to users(id) keep pointing
-- at the same uuids, the identity token's `sub` is that uuid, and no product has to translate. New
-- ids would mean rewriting every one of those columns inside a maintenance window.
--
-- Usage, from the EC2 host:
--
--   docker compose exec -T postgres psql -U identity -d identity \
--     -v ON_ERROR_STOP=1 -f - < Identity/scripts/import-platform-users.sql
--
-- The foreign-data wrapper is what makes this one statement rather than a dump-and-load. It reads
-- the platform database directly, so nothing is written to disk in between and there is no window in
-- which a file full of password hashes exists.

BEGIN;

CREATE EXTENSION IF NOT EXISTS postgres_fdw;

-- Recreated each run so a changed password or host does not need the old server dropped by hand.
DROP SERVER IF EXISTS platform_source CASCADE;

CREATE SERVER platform_source
    FOREIGN DATA WRAPPER postgres_fdw
    OPTIONS (host 'localhost', port '5432', dbname :'platform_db');

CREATE USER MAPPING FOR CURRENT_USER
    SERVER platform_source
    OPTIONS (user :'platform_user', password :'platform_password');

CREATE SCHEMA IF NOT EXISTS platform_import;

-- Only the columns identity owns. default_organization_id and notification_prefs are left behind on
-- purpose: they are platform facts, and importing them would put product state in the identity store
-- on day one.
IMPORT FOREIGN SCHEMA public
    LIMIT TO (users, auth_identities, device_sessions, refresh_tokens, auth_challenges)
    FROM SERVER platform_source
    INTO platform_import;

-- Refuse rather than half-import. Two accounts with the same address cannot both exist here — the
-- unique index would reject the second — and picking one silently would sign somebody into the wrong
-- account. citext makes the comparison case-insensitive, which is the collision the platform's own
-- index would already have caught but a future MobiStack import will not.
DO $$
DECLARE
    collisions text;
BEGIN
    SELECT string_agg(email::text, ', ')
    INTO collisions
    FROM (
        SELECT email
        FROM platform_import.users
        WHERE deleted_at IS NULL
        GROUP BY email
        HAVING count(*) > 1
    ) duplicates;

    IF collisions IS NOT NULL THEN
        RAISE EXCEPTION 'Refusing to import: these addresses appear more than once — %', collisions;
    END IF;
END $$;

-- BCrypt hashes cross unchanged. The cost factor travels inside the hash, so the platform's
-- strength-10 hashes verify against this service's strength-12 encoder without anybody resetting a
-- password; only hashes written from now on cost 12.
INSERT INTO users (
    id, version, email, email_verified_at, phone, phone_verified_at,
    password_hash, password_changed_at, full_name, display_name, avatar_url, job_title,
    timezone, locale, status, platform_admin, failed_login_attempts, locked_until,
    last_login_at, last_active_at, created_at, updated_at, created_by, updated_by, deleted_at)
SELECT
    id, version, email, email_verified_at, phone, phone_verified_at,
    password_hash, password_changed_at, full_name, display_name, avatar_url, job_title,
    timezone, locale, status, platform_admin, failed_login_attempts, locked_until,
    last_login_at, last_active_at, created_at, updated_at, created_by, updated_by, deleted_at
FROM platform_import.users
ON CONFLICT (id) DO NOTHING;

INSERT INTO auth_identities (
    id, version, user_id, provider, provider_subject, provider_email, raw_profile,
    linked_at, last_login_at, created_at, updated_at, created_by, updated_by)
SELECT
    id, version, user_id, provider, provider_subject, provider_email, raw_profile,
    linked_at, last_login_at, created_at, updated_at, created_by, updated_by
FROM platform_import.auth_identities
ON CONFLICT (id) DO NOTHING;

-- Sessions and their refresh tokens come across so that nobody is signed out by the cutover. Revoked
-- rows come too: the audit trail of who signed out when is part of what this table is for, and
-- dropping them would make a revoked session look like one that never existed.
INSERT INTO device_sessions (
    id, version, user_id, device_id, device_name, device_type, user_agent, ip_address,
    last_seen_at, revoked_at, revoked_reason, cookie_token_hash, cookie_expires_at,
    created_at, updated_at, created_by, updated_by)
SELECT
    id, version, user_id, device_id, device_name, device_type, user_agent, ip_address,
    last_seen_at, revoked_at, revoked_reason, cookie_token_hash, cookie_expires_at,
    created_at, updated_at, created_by, updated_by
FROM platform_import.device_sessions
ON CONFLICT (id) DO NOTHING;

-- Only live tokens. An expired or consumed refresh token has no use here, and the rotation chain
-- would drag in ancestors that expired months ago for no benefit; replaced_by is nulled for the same
-- reason, since a successor that was itself expired did not come across.
INSERT INTO refresh_tokens (
    id, version, user_id, session_id, token_hash, expires_at, used_at, revoked_at, replaced_by,
    created_at, updated_at, created_by, updated_by)
SELECT
    id, version, user_id, session_id, token_hash, expires_at, used_at, revoked_at, NULL,
    created_at, updated_at, created_by, updated_by
FROM platform_import.refresh_tokens
WHERE revoked_at IS NULL
  AND used_at IS NULL
  AND expires_at > now()
ON CONFLICT (id) DO NOTHING;

-- Unconsumed challenges only, so a magic link somebody is holding in their inbox right now still
-- works after the cutover. Consumed ones are spent and expired ones are dead.
INSERT INTO auth_challenges (
    id, version, purpose, user_id, destination, secret_hash, expires_at, consumed_at,
    attempts, max_attempts, ip_address, metadata,
    created_at, updated_at, created_by, updated_by)
SELECT
    id, version, purpose, user_id, destination, secret_hash, expires_at, consumed_at,
    attempts, max_attempts, ip_address, metadata,
    created_at, updated_at, created_by, updated_by
FROM platform_import.auth_challenges
WHERE consumed_at IS NULL
  AND expires_at > now()
ON CONFLICT (id) DO NOTHING;

-- The wrapper is torn down rather than left connected. Leaving it in place would mean a permanent
-- read path from identity into the platform database, which is exactly what the split removes.
DROP SCHEMA platform_import CASCADE;
DROP SERVER platform_source CASCADE;
DROP EXTENSION postgres_fdw;

COMMIT;

-- What to check before pointing the gateway here.
SELECT
    (SELECT count(*) FROM users)            AS users,
    (SELECT count(*) FROM auth_identities)  AS federated_logins,
    (SELECT count(*) FROM device_sessions WHERE revoked_at IS NULL) AS live_sessions,
    (SELECT count(*) FROM refresh_tokens)   AS live_refresh_tokens,
    (SELECT count(*) FROM auth_challenges)  AS pending_challenges;
