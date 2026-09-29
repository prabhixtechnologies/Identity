# Identity security flows

This note covers the hosted and API authentication paths after the security remediation work.

## Rate limiting

Public sign-in endpoints are throttled in Redis using hashed bucket keys for:

- client IP (trusted `X-Forwarded-For` only when the TCP peer is a configured proxy CIDR)
- account identifier (email on password login)
- destination (email or phone on issue endpoints such as magic link, OTP and password reset)

When Redis is unavailable, a tight in-memory fallback applies on the local node only.

## Magic links

Emailed links still open `GET /login/link?token=…` on the identity origin. That request validates the
token and renders a confirmation page without consuming it. Sign-in completes on `POST
/login/link/confirm` with the hosted CSRF token.

Mobile and API clients continue to consume links through `POST /api/v1/identity/auth/magic-link/verify`.

## Google sign-in

GIS `id_token` values are verified locally against Google's JWKS when possible (issuer, audience,
expiry and signature). Every accepted token is stored once in Redis by hash until expiry so replays
are rejected even if tokeninfo would still answer.

## Logout

Two paths coexist:

| Path | Use |
| --- | --- |
| `GET /logout` | Hosted sign-out when no OIDC `id_token_hint` is available. **Does not sign anyone out** — it renders a confirmation page with a CSRF token. |
| `POST /logout` | Completes hosted sign-out. Requires the CSRF token from the confirmation page (or any same-origin form that includes it). |
| `GET` or `POST /connect/logout` | RP-initiated OIDC logout when an `id_token_hint` is available (`@prabhixtechnologies/oidc-client` uses this when it still holds the id token). Unchanged. |

**Client contract:** `@prabhixtechnologies/oidc-client` should navigate to `GET ${issuer}/logout` (or assign `window.location`) when there is no id token. A bare `POST /logout` without CSRF is rejected and redirected back to the confirmation page rather than signing the user out.

Optional `return_to` on hosted logout is validated like the account page and only redirects to registered client URLs after a successful POST.

## Platform staff passkeys

Accounts with `platform_admin = true` require WebAuthn user verification during passkey sign-in.
Discoverable passkey sign-in checks the UV flag after the credential is resolved.

## Global revocation

Per user (unchanged):

`POST /internal/identity/users/revoke-tokens?id=<uuid>` with the service token revokes every device
session, every active refresh token, and adds the user to the shared deny list for that account.

Fleet-wide cutover:

`POST /internal/identity/sessions/revoke-all?reason=cutover&batchSize=200` with the service token
revokes all active device sessions and refresh tokens in bounded batches, marks affected users on the
shared deny list, emits one aggregate `ALL_SESSIONS_REVOKED` audit row (counts only, no secrets), and
is safe to call repeatedly (subsequent runs revoke zero rows).

## Internal service authentication

Every `/internal/**` request passes through a dedicated Spring Security chain (order 0) and
`InternalServiceAuthFilter` before controllers run.

| Requirement | Routes |
| --- | --- |
| Valid `X-Prabhix-Service-Token` (constant-time compare) | All `/internal/**` |
| Blank or missing configured token | Entire internal surface returns `FEATURE_DISABLED` |
| `X-Prabhix-Acting-User` (valid UUID) | `/internal/identity/admin/**` (reads and mutations) |
| Service token only (no acting user) | `POST /internal/identity/users/lookup`, `POST …/users/revoke-tokens`, `POST …/sessions/revoke-all` |

Failed token attempts are rate-limited and recorded as `INTERNAL_ACCESS_DENIED` with route and reason
only — never the presented secret. Controllers still call `ServiceTokenAuthenticator` for defence in
depth; a request the filter already verified skips duplicate throttling.

## Registration vs sign-in

`POST /api/v1/identity/auth/register` returns a generic `INVALID_CREDENTIALS` response when the email
is already taken. That response does **not** disable or alter the account — it only refuses to create
a duplicate. Existing users recover by signing in with `POST /api/v1/identity/auth/login` (or any
other sign-in path). Clients should treat a failed registration as “try sign-in or reset password”,
not as a lockout.
