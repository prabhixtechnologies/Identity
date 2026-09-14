# identity-spring-boot-starter

The client half of Prabhix Identity. A product backend adds this one dependency and gets:

| Bean | What it does |
|---|---|
| `IdentityTokenVerifier` | Verifies an RS256 access token against identity's published JWKS and returns an `IdentityToken` — subject, email, name, session id, `amr`. Nothing about authority: that is the product's job. |
| `IdentityKeySource` | The JWKS cache behind the verifier. Refreshes on an unknown `kid` (what a rotation looks like), rate-limited so a forged `kid` cannot cause a fetch per request. |
| `IdentityInternalClient` | `lookup` and `revokeTokens` for the user mirror and break-glass, and the `/internal/admin` surface — users, sessions, clients, keys, events — every call naming the acting staff member. |
| `IdentityUserMirror` | Pulls a user identity knows and the product does not into the product's `users` table, through the product's own `UserMirrorStore` bean. |
| `ServiceTokenGuard` | Constant-time check of `X-Prabhix-Service-Token` for a product's own `/internal/*` endpoints, plus the acting-user headers. |

There is deliberately no HMAC path and no token issuance. A product that could verify with a shared
secret could mint with it, which is the property the identity split exists to remove.

## Using it

```xml
<dependency>
    <groupId>com.prabhix</groupId>
    <artifactId>identity-spring-boot-starter</artifactId>
    <version>1.0.0</version>
</dependency>
```

```yaml
prabhix:
  identity:
    issuer: ${IDENTITY_ISSUER:}                       # blank = trust nobody
    jwks-uri: ${IDENTITY_JWKS_URI:}                   # default: <issuer>/.well-known/jwks.json
    internal-base-url: ${IDENTITY_INTERNAL_URL:http://identity:8081}
    service-token: ${IDENTITY_SERVICE_TOKEN:}
```

Provide a `UserMirrorStore` bean with the product's upsert, and `IdentityUserMirror` appears.
Every bean is `@ConditionalOnMissingBean`, so a test can replace `IdentityKeySource` with a stub
that returns a known public key.

The verifier throws `IdentityTokenException` with a `Reason` (`EXPIRED`, `INVALID`, `UNTRUSTED`);
the client throws `IdentityClientException` with a `Kind` (`DISABLED`, `UNAVAILABLE`, `NOT_FOUND`,
`REJECTED`). Products translate those into their own error codes in one place — the filter.

## Where it comes from

Published to GitHub Packages at `https://maven.pkg.github.com/prabhixtechnologies/Identity` by
`.github/workflows/ci.yml` on every push to `main` that changes `client/`. Consumers declare the
repository:

```xml
<repositories>
    <repository>
        <id>github</id>
        <url>https://maven.pkg.github.com/prabhixtechnologies/Identity</url>
    </repository>
</repositories>
```

and authenticate with a token that has `read:packages` — in CI, `actions/setup-java` with
`server-id: github` wires `GITHUB_TOKEN` in; on a laptop, a `<server><id>github</id>…` entry in
`~/.m2/settings.xml` with a classic PAT. To work on the starter and a product together, `mvn -f
client/pom.xml install` puts the same coordinates in the local repository and the product picks
them up first.

Bump `<version>` when the API changes; consumers pin, so a change nobody has adopted breaks nothing.
