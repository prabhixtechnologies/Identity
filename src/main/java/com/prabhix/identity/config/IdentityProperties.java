package com.prabhix.identity.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;
import java.util.List;

/**
 * @param serviceToken shared secret a product presents to read user records from {@code /internal}.
 *     A shared secret rather than mTLS or a signed assertion because there are three consumers on
 *     one host and the endpoint is not routed publicly; blank disables the endpoint entirely, which
 *     is the correct default for a deployment that has not been given one.
 */
@ConfigurationProperties(prefix = "prabhix.identity")
public record IdentityProperties(
        String issuer,
        Token token,
        Signing signing,
        Password password,
        Lockout lockout,
        Challenge challenge,
        SessionCookie sessionCookie,
        Urls urls,
        Sso sso,
        @DefaultValue Sms sms,
        @DefaultValue WhatsApp whatsApp,
        @DefaultValue WebAuthn webAuthn,
        @DefaultValue Mail mail,
        @DefaultValue List<Client> clients,
        @DefaultValue Platform platform,
        String serviceToken) {

    /**
     * The product that owns organizations, for the tenant half of signing up.
     *
     * <p>The one outbound call this service makes to a product of ours, and it exists because signup
     * creates two things in two databases: an account here, and an organization there. Presented with
     * {@link IdentityProperties#serviceToken()} — the same secret the platform presents coming the
     * other way, because it is one trust relationship and a second secret would be a second thing to
     * forget to rotate.
     *
     * @param internalBaseUrl reached across the container network rather than through the public
     *     hostname. Going out through Caddy would be a round trip through the internet to arrive back
     *     on this host, and the edge answers {@code /internal} with a 404 precisely so that nobody
     *     else can make this call.
     *     <p>{@code prabhix-backend} and not {@code backend}: MobiStack shares this network and also
     *     has a service called {@code backend}, and Docker's DNS returns both addresses for that name
     *     with no way to opt out. Half of all signups would provision against a different product.
     */
    public record Platform(
            @DefaultValue("http://prabhix-backend:8080") String internalBaseUrl) {
    }

    /**
     * The four emails that gate account access: magic link, OTP, password reset, verification.
     *
     * @param transport which way they leave. {@code AUTO} resolves to SES when a region is
     *     configured and SMTP otherwise, which is what makes local development reach Mailpit and
     *     production reach SES without either one naming the other's transport. An enum rather than
     *     a string so that a misspelling fails the context at startup instead of quietly selecting
     *     the fallback — a typo here would present as sign-in mail that never arrives.
     */
    public record Mail(
            @DefaultValue("security@prabhixtechnologies.com") String from,
            @DefaultValue("Prabhix Technologies") String fromName,
            @DefaultValue("AUTO") Transport transport,
            @DefaultValue Ses ses) {

        public enum Transport {
            AUTO, SES, SMTP
        }
    }

    /**
     * Amazon SES, used through the API rather than its SMTP interface.
     *
     * <p>SMTP submission would need a long-lived access key baked into the environment, because SES
     * SMTP credentials are an IAM secret run through a derivation. The API is reached with the
     * instance role instead, so there is no static credential to leak or rotate — which is the whole
     * reason the region is the only thing that normally has to be set.
     *
     * @param accessKey only for running outside AWS, where no role can be assumed. Left blank the
     *     credentials come from the default provider chain, which on the production box is the
     *     instance profile.
     * @param configurationSet optional; where SES publishes bounce and complaint events
     */
    public record Ses(
            @DefaultValue("") String region,
            @DefaultValue("") String accessKey,
            @DefaultValue("") String secretKey,
            @DefaultValue("") String configurationSet) {

        public boolean configured() {
            return region != null && !region.isBlank();
        }

        public boolean hasStaticCredentials() {
            return accessKey != null && !accessKey.isBlank()
                    && secretKey != null && !secretKey.isBlank();
        }
    }

    /**
     * Outbound SMS, for phone OTP sign-in.
     *
     * @param accountSid blank disables phone sign-in entirely, which is the right default: a
     *     deployment with no provider should refuse visibly rather than accept an OTP request and
     *     never deliver it.
     * @param messagingServiceSid preferred over {@code fromNumber} where both are set. For Indian
     *     destinations this is the one that carries DLT sender-id and template registration, without
     *     which the carrier drops the message and the API call still succeeds.
     */
    public record Sms(
            @DefaultValue("") String accountSid,
            @DefaultValue("") String authToken,
            @DefaultValue("") String fromNumber,
            @DefaultValue("") String messagingServiceSid) {
    }

    /**
     * WhatsApp OTP, sharing the Twilio account SID with {@link Sms}.
     *
     * @param fromNumber blank disables WhatsApp when a real SID is set. With {@code TWILIO_ACCOUNT_SID
     *     =mock} the logging sender is used regardless, so local development does not need a sandbox
     *     from-number.
     */
    public record WhatsApp(@DefaultValue("") String fromNumber) {
    }

    /**
     * Passkey / WebAuthn relying-party settings.
     *
     * @param rpId registrable domain scope for credentials (e.g. {@code localhost} or
     *     {@code prabhixtechnologies.com})
     * @param origins expected browser origins for the ceremony; a phishing page on another origin
     *     fails verification even if it somehow obtained the challenge
     */
    public record WebAuthn(
            @DefaultValue("localhost") String rpId,
            @DefaultValue("Prabhix Technologies") String rpName,
            @DefaultValue({"http://localhost:8081"}) List<String> origins) {
    }

    /**
     * A first-party OAuth client, seeded into {@code oauth2_registered_client} at startup.
     *
     * <p>Configured rather than migrated because redirect URIs are environment-specific — localhost in
     * development, real hostnames in production — and a migration that hard-codes one is wrong
     * everywhere else. Third-party clients, when there are any, are registered through the admin
     * console instead and never appear here.
     *
     * @param clientId stable public identifier, e.g. {@code prabhix-console}
     * @param name shown on the consent screen, for the clients that ever see one
     * @param secret blank for a public client — a browser SPA or a mobile app, neither of which can
     *     keep one. Those are secured by PKCE instead, which is why S256 is mandatory below.
     * @param redirectUris compared for exact equality, never by prefix or wildcard. A permissive match
     *     here is an open redirect, and an open redirect on {@code /authorize} hands the authorization
     *     code to whoever crafted the link.
     * @param postLogoutRedirectUris where RP-initiated logout may return to, matched the same way
     * @param scopes what this client may ask for. {@code openid} is required for an id_token.
     * @param firstParty skips consent. Asking somebody to authorise Prabhix to access Prabhix is
     *     noise, and teaching people to click through consent screens is its own hazard. Never set
     *     this for a client owned by anyone else.
     */
    public record Client(
            String clientId,
            String name,
            @DefaultValue("") String secret,
            @DefaultValue List<String> redirectUris,
            @DefaultValue List<String> postLogoutRedirectUris,
            @DefaultValue({"openid", "profile", "email"}) List<String> scopes,
            @DefaultValue("true") boolean firstParty) {

        public boolean isPublicClient() {
            return secret == null || secret.isBlank();
        }
    }

    /**
     * @param accessTokenTtl matches the platform's 15 minutes. Short because access tokens carry no
     *     revocation check of their own — a signature is valid until it expires, and the products
     *     verifying it offline cannot ask whether the session still exists.
     * @param refreshTokenTtl also how long a signed-in browser stays signed in, since the session
     *     cookie shares this knob
     */
    public record Token(
            @DefaultValue("PT15M") Duration accessTokenTtl,
            @DefaultValue("P30D") Duration refreshTokenTtl) {
    }

    /**
     * @param privateKey PKCS#8 PEM of the active signing key. Blank generates an ephemeral key,
     *     which {@code SigningKeyProvider} permits only under a local profile.
     * @param retiredPublicKeys X.509 PEM public keys that no longer sign but are still published in
     *     the JWKS. Rotation without these is an outage: every token signed by the old key fails
     *     verification the moment the new one takes over, and access tokens live for 15 minutes.
     */
    public record Signing(String privateKey, List<String> retiredPublicKeys) {
    }

    /**
     * @param bcryptStrength 12, the platform's setting. Imported MobiStack hashes were written at 12
     *     and platform's at 10; both verify regardless, because bcrypt stores the cost inside the
     *     hash. This only decides the cost of hashes written from now on.
     */
    public record Password(
            @DefaultValue("10") int minLength,
            @DefaultValue("12") int bcryptStrength) {
    }

    /**
     * @param maxFailedAttempts hardcoded at 5 in the platform. Configurable here because the number
     *     that stops credential stuffing and the number that stops locking out a legitimate user
     *     with a stale password manager entry are not obviously the same, and nobody could tune it.
     */
    public record Lockout(
            @DefaultValue("5") int maxFailedAttempts,
            @DefaultValue("PT15M") Duration duration) {
    }

    /** Magic links, OTPs, password resets and email verification. */
    public record Challenge(
            @DefaultValue("6") int otpLength,
            @DefaultValue("PT10M") Duration ttl,
            @DefaultValue("5") int maxAttempts) {
    }

    /**
     * @param domain the registrable parent domain, so every console hostname sees the same cookie.
     *     Empty means host-only, which is what you want in local development where there is no
     *     parent domain to share.
     * @param sameSite Lax, not None: the cookie is withheld from cross-site POSTs, so the exchange
     *     endpoint cannot be driven from another origin.
     */
    public record SessionCookie(
            @DefaultValue("pbx_session") String name,
            @DefaultValue("") String domain,
            @DefaultValue("true") boolean secure,
            @DefaultValue("Lax") String sameSite) {

        public String domainOrNull() {
            return domain == null || domain.isBlank() ? null : domain;
        }
    }

    /**
     * Where emailed links point.
     *
     * <p>These are console router paths, not API paths. The two drifted apart once already and every
     * emailed magic link 404'd, so they are configured as whole URLs rather than assembled from a
     * base and a guess.
     */
    public record Urls(String console, String admin) {
    }

    /** @param googleClientId blank disables Google sign-in rather than failing at request time */
    public record Sso(@DefaultValue("") String googleClientId) {
    }
}
