package com.prabhix.identity.mail;

import com.prabhix.identity.config.IdentityProperties;
import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sesv2.SesV2Client;
import software.amazon.awssdk.services.sesv2.model.EmailContent;
import software.amazon.awssdk.services.sesv2.model.GetAccountRequest;
import software.amazon.awssdk.services.sesv2.model.GetAccountResponse;
import software.amazon.awssdk.services.sesv2.model.GetEmailIdentityRequest;
import software.amazon.awssdk.services.sesv2.model.NotFoundException;
import software.amazon.awssdk.services.sesv2.model.RawMessage;
import software.amazon.awssdk.services.sesv2.model.SendEmailRequest;
import software.amazon.awssdk.services.sesv2.model.SendEmailResponse;
import software.amazon.awssdk.services.sesv2.model.SesV2Exception;

import jakarta.mail.Session;
import java.io.ByteArrayOutputStream;
import java.time.Duration;
import java.time.Instant;
import java.util.Properties;

/**
 * Amazon SES through its API, as raw MIME.
 *
 * <p>The API and not SES's SMTP interface, because SMTP submission needs a static access key stored
 * in the environment — SES SMTP credentials are an IAM secret put through a derivation — while the
 * API is reached with the instance role and has no credential to leak or rotate. Raw MIME and not
 * the structured content API, so that the message this sends is byte-for-byte the one the SMTP
 * transport would have sent, rather than a second rendering that only production exercises.
 */
@Slf4j
public class SesAuthMailTransport implements AuthMailTransport {

    /**
     * The probe makes two network calls and the health endpoint can be polled, so its answer is
     * cached. A minute: verification and sandbox status move on the order of days, and a permission
     * just granted or a domain just verified still takes effect without restarting the service.
     */
    private static final Duration PROBE_TTL = Duration.ofMinutes(1);

    private final IdentityProperties.Mail mail;
    private final SesV2Client client;
    /** MIME assembly only. No transport is configured on it; SES does the sending. */
    private final Session session = Session.getInstance(new Properties());
    private volatile Probe probe;

    public SesAuthMailTransport(IdentityProperties.Mail mail) {
        this(mail, build(mail.ses()));
    }

    /**
     * Takes the client so the probe can be tested against SES's real responses. Everything it
     * distinguishes — an unverified domain, a sandboxed account, a read denied to a send-only role —
     * is a live production state, and getting one backwards means reporting healthy for a
     * configuration that delivers nothing, or unhealthy for one that works.
     */
    SesAuthMailTransport(IdentityProperties.Mail mail, SesV2Client client) {
        this.mail = mail;
        this.client = client;
    }

    private static SesV2Client build(IdentityProperties.Ses ses) {
        var builder = SesV2Client.builder().region(Region.of(ses.region()));
        builder.credentialsProvider(ses.hasStaticCredentials()
                ? StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(ses.accessKey(), ses.secretKey()))
                : DefaultCredentialsProvider.create());
        return builder.build();
    }

    @Override
    public String id() {
        return "SES";
    }

    @Override
    public MimeMessage createMessage() {
        return new MimeMessage(session);
    }

    @Override
    public void send(MimeMessage message) {
        ByteArrayOutputStream raw = new ByteArrayOutputStream();
        try {
            message.writeTo(raw);
        } catch (Exception ex) {
            throw new AuthMailUndeliverable("could not serialise the message", ex);
        }

        SendEmailRequest.Builder request = SendEmailRequest.builder()
                .content(EmailContent.builder()
                        .raw(RawMessage.builder()
                                .data(SdkBytes.fromByteArray(raw.toByteArray()))
                                .build())
                        .build());

        String configurationSet = mail.ses().configurationSet();
        if (configurationSet != null && !configurationSet.isBlank()) {
            request.configurationSetName(configurationSet);
        }

        try {
            SendEmailResponse response = client.sendEmail(request.build());
            // The recipient is not logged, here or in the failure path. This runs for addresses that
            // may not have an account, and a log line proving one does is the enumeration leak that
            // the deliberately generic API response exists to prevent. The SES message id is enough
            // to find the message in SES's own logs, which may record the address.
            log.debug("SES accepted auth mail, message id {}", response.messageId());
        } catch (SesV2Exception ex) {
            // The SDK's own message omits the error code, which is the part that says why.
            throw new AuthMailUndeliverable("SES rejected the message: " + describe(ex), ex);
        } catch (SdkException ex) {
            throw new AuthMailUndeliverable("SES was unreachable: " + ex.getMessage(), ex);
        }
    }

    @Override
    public Status status() {
        Probe cached = probe;
        if (cached != null && Duration.between(cached.at(), Instant.now()).compareTo(PROBE_TTL) < 0) {
            return cached.status();
        }
        Probe fresh = new Probe(runProbe(), Instant.now());
        probe = fresh;
        if (!fresh.status().usable()) {
            log.warn("SES cannot send auth mail: {}", fresh.status().note());
        }
        return fresh.status();
    }

    /**
     * Asks the two questions that decide whether a send is accepted: may this account send at all,
     * and is the from-address an identity SES has verified. Checking only that a region is set is
     * what let the platform report healthy while delivering nothing.
     */
    private Status runProbe() {
        String accountNote;
        try {
            accountNote = accountNote();
        } catch (Unusable ex) {
            return Status.unusable(ex.getMessage());
        } catch (SesV2Exception ex) {
            if (!isAccessDenied(ex)) {
                return Status.unusable("SES rejected GetAccount: " + describe(ex));
            }
            // A send-only policy is the correct way to run this, and being refused the read says
            // nothing about whether a send would succeed.
            accountNote = "sending status unconfirmed (no ses:GetAccount permission)";
        } catch (SdkException ex) {
            // No credentials resolved at all, or SES unreachable. Definitive, and the failure that
            // a region check cannot see: the instance role is resolved on this call.
            return Status.unusable("SES is unreachable or has no credentials: " + ex.getMessage());
        }

        try {
            return Status.usable(join(accountNote, senderNote()));
        } catch (Unusable ex) {
            return Status.unusable(ex.getMessage());
        } catch (SesV2Exception ex) {
            if (!isAccessDenied(ex)) {
                return Status.unusable("SES rejected GetEmailIdentity: " + describe(ex));
            }
            return Status.usable(join(accountNote,
                    "sender identity unconfirmed (no ses:GetEmailIdentity permission)"));
        } catch (SdkException ex) {
            return Status.unusable("SES is unreachable: " + ex.getMessage());
        }
    }

    /**
     * @return a caveat about the account worth reporting, or null
     * @throws Unusable when the account may not send at all
     */
    private String accountNote() {
        GetAccountResponse account = client.getAccount(GetAccountRequest.builder().build());
        if (Boolean.FALSE.equals(account.sendingEnabled())) {
            return failWith("sending is disabled for this SES account"
                    + (account.enforcementStatus() == null
                    ? "" : " (enforcement status " + account.enforcementStatus() + ")"));
        }
        if (Boolean.FALSE.equals(account.productionAccessEnabled())) {
            // Not unusable: sends to verified recipients do succeed, and that is the state this
            // account is in today. Said out loud because to anyone else a sandboxed account presents
            // as sign-in mail that leaves and never arrives.
            return "account is in the SES sandbox, so only verified recipients receive mail";
        }
        return null;
    }

    /**
     * SES accepts a send only from an identity it has verified, which may be the whole domain or the
     * single address. Both are checked: either is a valid setup, and no domain identity is not
     * evidence that the address is unverified.
     *
     * @throws Unusable when neither can send
     */
    private String senderNote() {
        String from = mail.from();
        int at = from == null ? -1 : from.indexOf('@');
        if (at < 0) {
            return failWith("the from-address is not an email address: " + from);
        }
        String domain = from.substring(at + 1);

        Boolean domainVerified = verifiedForSending(domain);
        if (Boolean.TRUE.equals(domainVerified)) {
            return null;
        }
        Boolean addressVerified = verifiedForSending(from);
        if (Boolean.TRUE.equals(addressVerified)) {
            return "sending as a verified address rather than a verified domain";
        }
        if (domainVerified == null && addressVerified == null) {
            return failWith("neither " + domain + " nor " + from
                    + " is an SES identity in this account, so every send will be rejected");
        }
        return failWith("SES verification of " + domain
                + " is still pending; publish the DKIM CNAME records it asks for");
    }

    /** @return null when no such identity exists, otherwise whether it is verified for sending */
    private Boolean verifiedForSending(String identity) {
        try {
            return client.getEmailIdentity(GetEmailIdentityRequest.builder()
                            .emailIdentity(identity)
                            .build())
                    .verifiedForSendingStatus();
        } catch (NotFoundException ex) {
            return null;
        }
    }

    /** Declared as returning a value so it can be used in a {@code return} and keep the flow linear. */
    private static String failWith(String reason) {
        throw new Unusable(reason);
    }

    private static boolean isAccessDenied(SesV2Exception ex) {
        return ex.awsErrorDetails() != null
                && "AccessDeniedException".equals(ex.awsErrorDetails().errorCode());
    }

    private static String describe(SesV2Exception ex) {
        return ex.awsErrorDetails() == null
                ? ex.getMessage()
                : ex.awsErrorDetails().errorCode() + ": " + ex.awsErrorDetails().errorMessage();
    }

    private static String join(String first, String second) {
        if (first == null) {
            return second;
        }
        return second == null ? first : first + "; " + second;
    }

    /** Public so that Spring's inferred destroy method closes the SDK client on shutdown. */
    public void close() {
        client.close();
    }

    /** A state in which SES definitely will not deliver, as opposed to one that cannot be checked. */
    private static final class Unusable extends RuntimeException {
        Unusable(String message) {
            super(message);
        }
    }

    private record Probe(Status status, Instant at) {
    }
}
