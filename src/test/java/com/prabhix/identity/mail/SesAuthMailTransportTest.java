package com.prabhix.identity.mail;

import com.prabhix.identity.config.IdentityProperties;
import com.prabhix.identity.config.TestProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.sesv2.SesV2Client;
import software.amazon.awssdk.services.sesv2.model.GetAccountRequest;
import software.amazon.awssdk.services.sesv2.model.GetAccountResponse;
import software.amazon.awssdk.services.sesv2.model.GetEmailIdentityRequest;
import software.amazon.awssdk.services.sesv2.model.GetEmailIdentityResponse;
import software.amazon.awssdk.services.sesv2.model.NotFoundException;
import software.amazon.awssdk.services.sesv2.model.SesV2Exception;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Covers the sendability probe, because every branch of it is a state production has actually been
 * in — a sandboxed account, an unverified domain, a role allowed to send but not to read — and
 * getting one backwards means either reporting healthy for a configuration that delivers nothing, or
 * reporting a working one as broken and hiding the real failure behind a false alarm.
 */
class SesAuthMailTransportTest {

    private static final String FROM = "security@prabhixtechnologies.com";
    private static final String DOMAIN = "prabhixtechnologies.com";

    @Test
    @DisplayName("a verified domain on a production account is usable with nothing to report")
    void verifiedDomainIsUsable() {
        SesV2Client client = mock(SesV2Client.class);
        when(client.getAccount(any(GetAccountRequest.class))).thenReturn(account(true, true));
        when(client.getEmailIdentity(any(GetEmailIdentityRequest.class)))
                .thenReturn(identity(true));

        AuthMailTransport.Status status = transport(client).status();

        assertThat(status.usable()).isTrue();
        assertThat(status.note()).isNull();
    }

    @Test
    @DisplayName("a sandboxed account is usable, but says so — it delivers only to verified recipients")
    void sandboxIsUsableWithANote() {
        SesV2Client client = mock(SesV2Client.class);
        when(client.getAccount(any(GetAccountRequest.class))).thenReturn(account(true, false));
        when(client.getEmailIdentity(any(GetEmailIdentityRequest.class)))
                .thenReturn(identity(true));

        AuthMailTransport.Status status = transport(client).status();

        assertThat(status.usable()).isTrue();
        assertThat(status.note()).contains("sandbox");
    }

    @Test
    @DisplayName("an account with sending disabled cannot deliver at all")
    void sendingDisabledIsUnusable() {
        SesV2Client client = mock(SesV2Client.class);
        when(client.getAccount(any(GetAccountRequest.class))).thenReturn(account(false, true));

        AuthMailTransport.Status status = transport(client).status();

        assertThat(status.usable()).isFalse();
        assertThat(status.note()).contains("sending is disabled");
    }

    @Test
    @DisplayName("an unknown sender identity is unusable: SES rejects every send from it")
    void unknownIdentityIsUnusable() {
        SesV2Client client = mock(SesV2Client.class);
        when(client.getAccount(any(GetAccountRequest.class))).thenReturn(account(true, true));
        when(client.getEmailIdentity(any(GetEmailIdentityRequest.class)))
                .thenThrow(NotFoundException.builder().message("not found").build());

        AuthMailTransport.Status status = transport(client).status();

        assertThat(status.usable()).isFalse();
        assertThat(status.note()).contains(DOMAIN).contains("every send will be rejected");
    }

    @Test
    @DisplayName("a domain that exists but is still pending verification is unusable")
    void pendingVerificationIsUnusable() {
        SesV2Client client = mock(SesV2Client.class);
        when(client.getAccount(any(GetAccountRequest.class))).thenReturn(account(true, true));
        when(client.getEmailIdentity(any(GetEmailIdentityRequest.class)))
                .thenReturn(identity(false));

        AuthMailTransport.Status status = transport(client).status();

        assertThat(status.usable()).isFalse();
        assertThat(status.note()).contains("still pending");
    }

    @Test
    @DisplayName("a verified address without a verified domain still sends")
    void verifiedAddressAloneIsUsable() {
        SesV2Client client = mock(SesV2Client.class);
        when(client.getAccount(any(GetAccountRequest.class))).thenReturn(account(true, true));
        // The domain is not an identity at all; the single address is.
        when(client.getEmailIdentity(GetEmailIdentityRequest.builder().emailIdentity(DOMAIN).build()))
                .thenThrow(NotFoundException.builder().message("not found").build());
        when(client.getEmailIdentity(GetEmailIdentityRequest.builder().emailIdentity(FROM).build()))
                .thenReturn(identity(true));

        AuthMailTransport.Status status = transport(client).status();

        assertThat(status.usable()).isTrue();
        assertThat(status.note()).contains("verified address");
    }

    @Test
    @DisplayName("a send-only role is denied the reads, which is not evidence that sending fails")
    void accessDeniedStaysUsable() {
        SesV2Client client = mock(SesV2Client.class);
        when(client.getAccount(any(GetAccountRequest.class))).thenThrow(accessDenied());
        when(client.getEmailIdentity(any(GetEmailIdentityRequest.class))).thenThrow(accessDenied());

        AuthMailTransport.Status status = transport(client).status();

        assertThat(status.usable()).isTrue();
        assertThat(status.note()).contains("unconfirmed");
    }

    @Test
    @DisplayName("no resolvable credentials is unusable — the failure a region check cannot see")
    void missingCredentialsIsUnusable() {
        SesV2Client client = mock(SesV2Client.class);
        when(client.getAccount(any(GetAccountRequest.class))).thenThrow(
                SdkClientException.create("Unable to load credentials from any of the providers"));

        AuthMailTransport.Status status = transport(client).status();

        assertThat(status.usable()).isFalse();
        assertThat(status.note()).contains("credentials");
    }

    @Test
    @DisplayName("the probe is cached, so polling the health endpoint does not hammer SES")
    void probeIsCached() {
        SesV2Client client = mock(SesV2Client.class);
        when(client.getAccount(any(GetAccountRequest.class))).thenReturn(account(true, true));
        when(client.getEmailIdentity(any(GetEmailIdentityRequest.class)))
                .thenReturn(identity(true));

        SesAuthMailTransport transport = transport(client);
        transport.status();
        transport.status();
        transport.status();

        org.mockito.Mockito.verify(client, org.mockito.Mockito.times(1))
                .getAccount(any(GetAccountRequest.class));
    }

    private SesAuthMailTransport transport(SesV2Client client) {
        IdentityProperties.Mail mail = TestProperties.mail(
                FROM, new IdentityProperties.Ses("ap-south-1", "", "", ""));
        return new SesAuthMailTransport(mail, client);
    }

    private static GetAccountResponse account(boolean sendingEnabled, boolean productionAccess) {
        return GetAccountResponse.builder()
                .sendingEnabled(sendingEnabled)
                .productionAccessEnabled(productionAccess)
                .build();
    }

    private static GetEmailIdentityResponse identity(boolean verified) {
        return GetEmailIdentityResponse.builder().verifiedForSendingStatus(verified).build();
    }

    private static SesV2Exception accessDenied() {
        return (SesV2Exception) SesV2Exception.builder()
                .awsErrorDetails(AwsErrorDetails.builder()
                        .errorCode("AccessDeniedException")
                        .errorMessage("not authorized to perform this operation")
                        .build())
                .message("not authorized")
                .build();
    }
}
