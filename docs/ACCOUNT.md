# Account

One place to change the person, not the product. Every Prabhix app deep-links here rather than
growing a settings screen of its own: password, passkeys, email and Google are facts about the
account, and a copy of them in the console, Mailroom and a phone is three places to be wrong.

The page is `{issuer}/account`. Products send the browser with `return_to` set to a redirect URI or
post-logout URI they already registered:

```
https://id.prabhixtechnologies.com/account?return_to=https://app.prabhixtechnologies.com/
```

`return_to` is matched exactly against those registered URLs. Anything else is ignored, so this
cannot be used as an open redirect. "Back to app" on the page is that URL, or absent.

The browser session is the same cookie the hosted login pages set. An unauthenticated visit is sent
to `/login` and resumes here afterwards.

## Grace period

`POST /api/v1/identity/auth/deletion` (and the button on the page) sets `users.deletion_requested_at`. The
account stays usable. Nothing in this service completes the deletion: an operator, or a job that
does not yet exist, is what actually removes the row, and only after **30 days**.

`DELETE /api/v1/identity/auth/deletion` clears the timestamp. Cancelling on day 29 is the same as never
having asked.

The point of the delay is the person who clicked the wrong button, and the product that still has
foreign keys to this `sub`. Instant deletion would be a support ticket in two databases.

## Self-service APIs

Authenticated with a bearer token or the hosted session. JSON, same error body as the rest of
identity.

| | |
| --- | --- |
| `POST /api/v1/identity/auth/password/change` | `{ currentPassword, newPassword }`. Stays signed in: this is not a reset. |
| `PUT /api/v1/identity/auth/profile` | Partial: `name`, `displayName`, `phone`, `timezone`, `locale`. |
| `POST /api/v1/identity/auth/email/change/request` | Sends a link to the **new** address. |
| `POST /api/v1/identity/auth/email/change/confirm` | Public. `{ token }` from the link. Also `GET /account/email/confirm?token=`. |
| `GET /api/v1/identity/webauthn/credentials` | Passkeys: `id`, `label`, `createdAt`, `lastUsedAt`, `backedUp`. |
| `DELETE /api/v1/identity/webauthn/credentials/{id}` | Refused with `LAST_CREDENTIAL` if it is the only remaining factor. |
| `DELETE /api/v1/identity/auth/identities/google` | Same last-factor rule. |
| `POST /api/v1/identity/auth/deletion` | Sets the timestamp. Does not sign the person out. |
| `DELETE /api/v1/identity/auth/deletion` | Clears it. |

A factor here is a password, a Google link, or a passkey. Magic-link and OTP are not counted: they
are always available for an address, so treating them as remaining would let somebody delete the
last thing they registered.

Enrol a passkey with the existing `POST /api/v1/identity/webauthn/register/{options,finish}` (bearer) or
`POST /account/passkey/{options,finish}` (hosted session).

## Admin

Staff do not call these from a browser. The oneOps admin BFF does, with the service token and
`X-Prabhix-Acting-User`, through `IdentityInternalClient`. Paths and JSON match `IdentityAdmin`
exactly. Every write records an `ADMIN_*` event naming that person.
