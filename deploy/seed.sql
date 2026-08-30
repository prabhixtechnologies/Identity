-- First run against an empty identity database: the one account that can sign in.
--
-- Flyway's baseline here creates eight tables and inserts nothing at all, which is correct — this
-- service has no reference data. The OAuth clients are not seeded either: RegisteredClientSeeder
-- registers everything under prabhix.identity.clients on every boot and updates an existing
-- client_id in place, so a redirect URI change is a config change rather than a SQL edit. That
-- leaves exactly one thing missing on a fresh database, which is a person.
--
-- Run Platform/deploy/seed.sql as well, with the same owner_email, owner_password and owner_id. The
-- two databases are joined by that id and nothing else: Identity signs a token whose `sub` is the id
-- from this table, and the platform looks up its own users row by that same uuid. Seed one side and
-- the other has nobody to authorize; seed both with different ids and the sign-in succeeds and then
-- every API call fails with "this account is not provisioned on the platform".
--
--   psql "host=$RDS user=identity dbname=identity sslmode=require" \
--     -v ON_ERROR_STOP=1 \
--     -v owner_email=you@prabhixtechnologies.com \
--     -v owner_password='<something long>' \
--     -v owner_name='Your Name' \
--     -f deploy/seed.sql
--
-- Locally:
--
--   docker compose exec -T postgres psql -U identity -d identity -v ON_ERROR_STOP=1 \
--     -v owner_password='dev-password' -f - < ../Identity/deploy/seed.sql
--
-- The password is hashed by pgcrypto at bcrypt cost 12, matching the bcrypt-strength this service is
-- configured with. Bcrypt records its cost inside the hash, so even a later change to that setting
-- leaves this hash verifying.
--
-- Safe to run twice: the insert is guarded on the id and the promotion below is an idempotent UPDATE,
-- so a second run rotates the password and clears a lockout rather than failing.

\set ON_ERROR_STOP on

-- admin@ rather than owner@, and it must match Platform/deploy/seed.sql. This address has to receive
-- mail: owner@ is not a mailbox at the domain's mail host, so the first magic link sent to it was
-- rejected outright, which for a passwordless sign-in means locked out.
\if :{?owner_email}
\else
  \set owner_email 'admin@prabhixtechnologies.com'
\endif

\if :{?owner_name}
\else
  \set owner_name 'Prabhix Owner'
\endif

-- Must match Platform/deploy/seed.sql, which defaults to the same constant.
\if :{?owner_id}
\else
  \set owner_id '00000000-0000-4000-8000-000000000002'
\endif

-- RAISE rather than \quit, which takes no status and would exit 0 — a seed that silently did
-- nothing is worse than one that failed.
\if :{?owner_password}
\else
  DO $$ BEGIN
    RAISE EXCEPTION 'owner_password is required: psql -v owner_password=<value> -f deploy/seed.sql';
  END $$;
\endif

BEGIN;

-- Two ways the id and the address can disagree with what is already here, and both are refused.
--
-- Neither would fail on its own. An id held by a different address fails on the primary key, which
-- reports a constraint name and no hint that owner_id is the problem. An address held by a different
-- id fails at nothing at all: the insert below is guarded on both, so it skips, the script reports
-- success, and the owner_id that was carefully passed is quietly ignored — which is the worse of the
-- two, because a mismatch between this table and the platform's is precisely what breaks sign-in, and
-- it breaks it after the login succeeds rather than at it.
--
-- The conditions are read out here and the raise is separate, rather than one PL/pgSQL block doing
-- both. psql does not substitute its variables inside dollar quotes — the body of a DO block is one
-- string literal to it — so :'owner_id' inside $$ ... $$ reaches the server verbatim and is a syntax
-- error. Hence \gset for the lookups, where substitution does happen, and constant messages inside.
SELECT
  EXISTS (
    SELECT 1 FROM users WHERE id = :'owner_id' AND email <> :'owner_email'::citext
  ) AS id_taken,
  COALESCE(
    (SELECT email::text FROM users WHERE id = :'owner_id' AND email <> :'owner_email'::citext),
    ''
  ) AS id_owner,
  EXISTS (
    SELECT 1 FROM users WHERE email = :'owner_email'::citext AND id <> :'owner_id'
  ) AS email_moved,
  COALESCE(
    (SELECT id::text FROM users WHERE email = :'owner_email'::citext AND id <> :'owner_id'),
    ''
  ) AS email_id
\gset

\if :id_taken
  \echo 'owner_id' :'owner_id' 'already belongs to' :'id_owner'
  DO $$ BEGIN
    RAISE EXCEPTION 'owner_id already belongs to a different address. Pass the same -v owner_id '
                    'used for the platform seed, or use the address above as owner_email.';
  END $$;
\endif

\if :email_moved
  \echo 'This address is already seeded under id' :'email_id' 'not' :'owner_id'
  DO $$ BEGIN
    RAISE EXCEPTION 'This address already exists under a different id. Reseed with -v owner_id set '
                    'to the id above so both databases agree, or delete the row first.';
  END $$;
\endif

-- email is citext and the unique index is on the column itself, so casing is already one address.
--
-- email_verified_at is set because whoever ran this typed the address. Login does not check it —
-- CredentialService only rejects DISABLED, locked and a wrong password — but the console shows an
-- unverified banner and the first thing a fresh install should not do is nag its own owner.
--
-- platform_admin stays false. This column survives the bulk import and nothing reads it: staff
-- authority lives in the platform's platform_staff_roles table, and the platform ignores identity's
-- copy on purpose, so that a compromised identity service cannot promote itself over there. Setting
-- it true here would grant nothing and imply otherwise.
INSERT INTO users (id, email, full_name, password_hash, password_changed_at, email_verified_at,
                   status, platform_admin)
SELECT :'owner_id',
       :'owner_email',
       :'owner_name',
       crypt(:'owner_password', gen_salt('bf', 12)),
       now(),
       now(),
       'ACTIVE',
       false
WHERE NOT EXISTS (SELECT 1 FROM users WHERE id = :'owner_id' OR email = :'owner_email'::citext);

-- Runs whether or not the insert did, which is the point of a second run: it rotates the password,
-- clears a lockout from failed sign-ins, and brings a DISABLED account back. This is the way back in
-- when nobody can sign in to fix it through the console.
UPDATE users
SET full_name           = :'owner_name',
    password_hash       = crypt(:'owner_password', gen_salt('bf', 12)),
    password_changed_at = now(),
    status              = 'ACTIVE',
    failed_login_attempts = 0,
    locked_until        = NULL,
    deleted_at          = NULL,
    updated_at          = now()
WHERE email = :'owner_email'::citext;

COMMIT;

-- ---------------------------------------------------------------------------------------------
-- What it built
-- ---------------------------------------------------------------------------------------------

\echo ''
\echo 'Seeded:'
SELECT id, email, full_name, status,
       email_verified_at IS NOT NULL AS email_verified,
       left(password_hash, 7)        AS hash
FROM users
WHERE email = :'owner_email'::citext;

\echo ''
\echo 'Registered OAuth clients (written by the service on boot, not by this script):'
SELECT client_id, client_name, redirect_uris FROM oauth2_registered_client ORDER BY client_id;

\echo ''
\echo 'If that list is empty the service has not started yet, or prabhix.identity.clients is unset —'
\echo 'the authorization code flow cannot complete until it has run.'
\echo ''
\echo 'The id above must match the platform users row. Check with:'
\echo '  psql -d oneops -tAc "SELECT id, email, platform_admin FROM users"'
