-- Seeds the identity database from MobiStack's users table.
--
-- Run once before pointing MobiStack web at Identity. Reruns are safe: every insert is
-- ON CONFLICT DO NOTHING (any unique violation — id or email), so a second run adds only
-- what a first run missed and never overwrites what identity has since changed.
--
-- Ids are preserved deliberately. The Identity token's `sub` is that uuid, and MobiStack's
-- users.id must match so JwtAuthenticationFilter can resolve the local row without a remap.
-- When a MobiStack email already exists under a different Identity id (platform import),
-- the row is skipped and the filter falls back to findWithRolesByEmail.
--
-- MobiStack's schema is not Identity's. Columns are transformed (bool verified → timestamps,
-- active → status, failed_logins → failed_login_attempts). Product-local fields (shop_id,
-- must_change_pw, system_admin) are left behind: they are not Identity facts.
--
-- Usage, from the EC2 host:
--
--   psql "host=$RDS user=prabhix dbname=identity sslmode=require" \
--     -v ON_ERROR_STOP=1 \
--     -v mobistack_db=mobistack \
--     -v mobistack_user=prabhix \
--     -v mobistack_password='<the mobistack database password>' \
--     -f Identity/scripts/import-mobistack-users.sql
--
-- The connecting role needs rds_superuser, or CREATE EXTENSION on the next line is refused.

\set ON_ERROR_STOP on

\if :{?mobistack_host}
\else
  \set mobistack_host 'localhost'
\endif

\if :{?mobistack_port}
\else
  \set mobistack_port '5432'
\endif

\if :{?mobistack_db}
\else
  \set mobistack_db 'mobistack'
\endif

\if :{?mobistack_user}
\else
  DO $$ BEGIN
    RAISE EXCEPTION 'mobistack_user is required: psql -v mobistack_user=... -v mobistack_password=...';
  END $$;
\endif

\if :{?mobistack_password}
\else
  DO $$ BEGIN
    RAISE EXCEPTION 'mobistack_password is required';
  END $$;
\endif

BEGIN;

CREATE EXTENSION IF NOT EXISTS postgres_fdw;

DROP SERVER IF EXISTS mobistack_source CASCADE;

CREATE SERVER mobistack_source
    FOREIGN DATA WRAPPER postgres_fdw
    OPTIONS (host :'mobistack_host', port :'mobistack_port', dbname :'mobistack_db');

CREATE USER MAPPING FOR CURRENT_USER
    SERVER mobistack_source
    OPTIONS (user :'mobistack_user', password :'mobistack_password');

CREATE SCHEMA IF NOT EXISTS mobistack_import;

IMPORT FOREIGN SCHEMA public
    LIMIT TO (users)
    FROM SERVER mobistack_source
    INTO mobistack_import;

-- Refuse rather than half-import. Two MobiStack accounts with the same address cannot both
-- land here — the unique index would reject the second — and picking one silently would sign
-- somebody into the wrong account.
DO $$
DECLARE
    collisions text;
BEGIN
    SELECT string_agg(email::text, ', ')
    INTO collisions
    FROM (
        SELECT lower(email) AS email
        FROM mobistack_import.users
        GROUP BY lower(email)
        HAVING count(*) > 1
    ) duplicates;

    IF collisions IS NOT NULL THEN
        RAISE EXCEPTION 'Refusing to import: these addresses appear more than once — %', collisions;
    END IF;
END $$;

-- BCrypt hashes cross unchanged. MobiStack writes strength-12; Identity's encoder verifies any
-- cost factor stored inside the hash.
INSERT INTO users (
    id, version, email, email_verified_at, phone, phone_verified_at,
    password_hash, password_changed_at, full_name, display_name, avatar_url, job_title,
    timezone, locale, status, platform_admin, failed_login_attempts, locked_until,
    last_login_at, last_active_at, created_at, updated_at, created_by, updated_by, deleted_at)
SELECT
    u.id,
    u.version,
    u.email,
    CASE WHEN u.email_verified THEN COALESCE(u.created_at, now()) ELSE NULL END,
    u.phone,
    CASE WHEN u.phone_verified THEN COALESCE(u.created_at, now()) ELSE NULL END,
    u.password_hash,
    u.updated_at,
    u.full_name,
    NULL,
    LEFT(u.avatar_url, 500),
    NULL,
    'Asia/Kolkata',
    'en-IN',
    CASE WHEN u.active THEN 'ACTIVE' ELSE 'DISABLED' END,
    false,
    u.failed_logins,
    u.locked_until,
    u.last_login_at,
    NULL,
    u.created_at,
    u.updated_at,
    u.created_by,
    u.updated_by,
    NULL
FROM mobistack_import.users u
ON CONFLICT DO NOTHING;

DROP SCHEMA mobistack_import CASCADE;
DROP SERVER mobistack_source CASCADE;
DROP EXTENSION postgres_fdw;

COMMIT;

SELECT count(*) AS users FROM users;
