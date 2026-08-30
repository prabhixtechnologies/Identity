# Prabhix Identity

Authentication for every Prabhix product. It answers one question — *who is this* — and signs a
token that says so. It deliberately does not answer *what may they do*, which each product resolves
from its own database.

Served at `id.prabhixtechnologies.com`, and reached through the shared API origin at
`api.prabhixtechnologies.com/api/v1/auth/*`.

## Why it is separate, and why authorization is not

The two products only look alike. Platform has `organizations`, an `org` claim and about fifty
permissions; MobiStack has `shops`, a `shop` claim, an inventory and sales permission set, billing
entitlements returned from `/auth/me`, and a per-device session limit. A service that owned both
permission models would be a distributed monolith: changing a repair-shop permission would mean
releasing the thing that signs everybody's tokens.

So the split is:

| Here | In each product |
| --- | --- |
| Credentials, lockout, password reset | Memberships, roles, permissions |
| Sessions, refresh tokens, device sessions | Invitations |
| OTP and magic-link challenges | Tenant scoping and every `@PreAuthorize` |
| Token issuance and revocation | Billing entitlements and device limits |

## The token contract

Claims: `sub`, `email`, `email_verified`, `name`, `sid`, `amr`. No product permissions, by design.

Products resolve permissions per request from their own database — the platform already does, behind
a five-minute Redis cache in `PermissionResolver`. That is strictly better than the current
behaviour, where permissions freeze into the JWT at sign-in and a revoked role keeps working until
the access token expires.

Active tenant travels in the `X-Prabhix-Org` header, validated against membership, rather than as a
token claim.

The sign-in response changed shape to match. It carries `accessToken`, `refreshToken`,
`expiresInSeconds` and `sessionId` — no `organizationId` and no `permissions`. A client that needs
those calls the product's own `/me`, which is the only thing that can answer them correctly.

## Endpoints

Paths are unchanged from the platform's `AuthController`, so Caddy can route `/api/v1/auth/*` here
without any client learning a new URL.

| | |
| --- | --- |
| `POST /api/v1/auth/register` | Create an account. No `organizationName`: creating an organization is a platform action, and this service does not know what one is. |
| `POST /api/v1/auth/login` | Email and password. |
| `POST /api/v1/auth/refresh` | Rotate a refresh token. |
| `POST /api/v1/auth/session/token` | Exchange the shared browser cookie. Nothing is rotated, so two hostnames can call it at the same instant. |
| `POST /api/v1/auth/logout` | Revoke this session. |
| `GET /api/v1/auth/me` | Who you are. Not what you may do. |
| `GET /api/v1/auth/sessions`, `DELETE /api/v1/auth/sessions/{id}` | List and revoke your own devices. |
| `POST /api/v1/auth/magic-link/{request,verify}` | Sign in by emailed link. |
| `POST /api/v1/auth/otp/{request,verify}` | Sign in by emailed code. |
| `POST /api/v1/auth/password/{forgot,reset}` | Password reset. |
| `POST /api/v1/auth/email/verify/{request,confirm}` | Confirm an address. |
| `POST /api/v1/auth/sso/google` | Google sign-in. |
| `POST /internal/users/lookup` | For a product filling its local `users` mirror. Guarded by `X-Prabhix-Service-Token`, and not routed publicly. |
| `POST /internal/users/{id}/revoke-tokens` | Break-glass revocation of every token for one account. |

### The user mirror

Each product keeps a thin local `users` row keyed by the identity `sub`. That is not duplication for
its own sake: twenty-one tables in the platform alone hold a foreign key to `users(id)` —
`created_by`, `assignee_id`, `organization_memberships.user_id` — and those cannot point across a
service boundary. Rewriting them to hold an unenforced id would trade referential integrity for
architectural purity.

Products pull, on demand, the first time they see a token naming a user they have no row for. There
is no message bus to make a push reliable, and on-demand is exactly when the row is needed. The cost
is a mirror that can be minutes stale after a name change, which is the right thing to be wrong
about.

### Auth mail

The four emails that gate account access — magic link, OTP, password reset, verification — are sent
from here over SMTP, not handed to the platform's mail subsystem. Calling the platform would make
identity depend on a product meant to sit on top of it, and identity has to work before any product
does. SMTP submission is the dependency instead; the self-hosted mail server and SES both speak it.

**A send failure fails the request.** It is not logged and swallowed. The platform once reported
success for mail it had only written to a log and marked it `SENT`; a magic link silently dropped is
that same bug with a locked-out user at the end of it.

## Data

Its own Postgres database, `identity`, on the same instance as the platform's `oneops`, owned by its
own `identity` role. A separate database rather than a schema, and a separate role rather than the
platform's, so "the platform cannot read the users table" is enforced by the credentials rather than
left to convention — a database the platform's own user owned would not be a boundary at all.

Five tables, copied column-for-column from the platform's schema so an import is a straight insert:
`users`, `auth_identities`, `device_sessions`, `refresh_tokens`, `auth_challenges`.
Two columns did not come across — `users.default_organization_id` and `users.notification_prefs` —
because only one product could ever populate them.

Redis is shared with the platform, also on purpose. The deny list is one set of `pbx:deny:*` keys
that identity writes and every product reads; two instances would mean a revocation only half the
fleet saw.

### Importing the platform's users

`scripts/import-platform-users.sql`, run once before the gateway is pointed here. Ids are preserved,
so every existing foreign key keeps working and no product has to translate. BCrypt hashes cross
unchanged — the cost factor travels inside the hash, so the platform's strength-10 and MobiStack's
strength-12 both verify against this service's strength-12 encoder with nobody resetting a password.

The script refuses to run if two live accounts share an address, rather than picking one.

### RS256, not HS256

Both products sign HS256 with a shared secret today. Across services that is the wrong shape: with a
symmetric secret, verifying a token and minting one are the same capability, so any service given
the secret so it can check a token could equally issue itself an administrator's.

This service signs RS256 and publishes the public half. A product can verify offline and cannot
sign.

- `GET /.well-known/openid-configuration`
- `GET /.well-known/jwks.json`

Both are public and cacheable for ten minutes. A public key is not a secret, and every product reads
them before it can accept a single request.

The discovery document advertises only what exists: `grant_types_supported` is `refresh_token` and
nothing else. Sign-in is password, OTP, magic link and Google, none of which are OAuth grants, and
offering a conformant client an `authorization_code` endpoint that is not implemented would fail in
a way that looks like our bug.

## Running it

```bash
mvn spring-boot:run
```

With no `IDENTITY_SIGNING_KEY`, a throwaway key is generated at startup and a warning is logged.
That is allowed only under a local profile, because otherwise it fails quietly in the worst way:
signing works and verification works, and then a restart or a second replica invalidates tokens for
reasons nobody can see.

Generate a real key with:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out identity-signing.pem
```

| Variable | Purpose |
| --- | --- |
| `IDENTITY_ISSUER` | The `iss` claim and the base of both well-known URLs. Must be the address clients actually reach. Changing it invalidates every token already issued, since verification requires an exact match. |
| `IDENTITY_SIGNING_KEY` | PKCS#8 PEM of the active key. Line breaks may arrive as literal `\n`; that is handled. |
| `IDENTITY_RETIRED_PUBLIC_KEYS` | X.509 PEM public keys that no longer sign but are still published. |
| `IDENTITY_ACCESS_TTL` | Default `PT15M`, matching the platform. |
| `IDENTITY_REFRESH_TTL` | Default `P30D`. Also how long a signed-in browser stays signed in, since the session cookie shares this knob. |
| `IDENTITY_DB_URL`, `IDENTITY_DB_USER`, `IDENTITY_DB_PASSWORD` | Its own database. |
| `REDIS_HOST`, `REDIS_PASSWORD` | Shared with the products, for the deny list. |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD` | Where auth mail goes. |
| `CONSOLE_URL`, `ADMIN_URL` | Where emailed links point. Console **router** paths, not API paths — these drifted apart once and every magic link 404'd. |
| `SESSION_COOKIE_DOMAIN` | The registrable parent domain, so one sign-in covers every Prabhix hostname. Empty means host-only, which is right locally. |
| `GOOGLE_CLIENT_ID` | Blank disables Google sign-in rather than failing at request time. |
| `IDENTITY_SERVICE_TOKEN` | What a product presents to `/internal`. Blank disables the endpoint, which is the right default for a deployment nobody gave one. |

### Rotating the signing key

1. Generate the new key.
2. Put the **old public** key in `IDENTITY_RETIRED_PUBLIC_KEYS` and the new private key in
   `IDENTITY_SIGNING_KEY`, in the same deploy.
3. After one access-token lifetime, remove the retired entry.

Skipping step 2 is an outage: every token issued in the previous fifteen minutes stops verifying the
moment the new key takes over. The `kid` is the RFC 7638 thumbprint of the key itself rather than a
name someone picked, so it is stable across restarts for the same key and necessarily different for a
different one — a rotation cannot reuse an id and leave clients verifying against the wrong half of a
pair.

## Build

Production targets Java 25, the current LTS. `-Djava.version=17` builds on an older local JDK, as in
the platform — it only lowers `--release`, and nothing here needs a newer language level to compile.

```bash
mvn -Djava.version=17 test              # unit tests
mvn -Djava.version=17 test -Pintegration  # also the Testcontainers-backed ones
```

Integration tests are tagged `integration` and named `*IntegrationTest`, matching the platform
backend. They run against real Postgres rather than H2: the schema uses `citext` and `jsonb`, and a
substitute database would let a migration that cannot apply in production pass here.

### Email addresses are normalized in Java, not by `citext`

`citext` columns do **not** make lookups case-insensitive through JDBC. pgjdbc binds a `String` as
`varchar`, and PostgreSQL resolves `citext = varchar` to `text = text`, which is case-sensitive.
Uniqueness still folds case, because that comparison is `citext` against `citext` with no parameter
involved — so left alone you get the worst split possible: an address cannot be registered twice, but
looking it up finds nothing.

So every address is folded through `Emails.normalize` on the way in (enforced in the entity setters)
and on the way out (the `findActiveByEmail`-style repository methods). `citext` stays as a
database-level guard for the writes that bypass this code, such as `scripts/import-platform-users.sql`
and any psql session.
