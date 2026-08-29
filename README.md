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

Production targets Java 21. `-Djava.version=17` builds on an older local JDK, as in the platform —
nothing here needs 21 to compile.

```bash
mvn -Djava.version=17 test
```
