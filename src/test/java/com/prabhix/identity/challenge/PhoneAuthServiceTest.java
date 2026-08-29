package com.prabhix.identity.challenge;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.session.SignInService;
import com.prabhix.identity.sms.SmsSender;
import com.prabhix.identity.user.CredentialService;
import com.prabhix.identity.user.IdentityUser;
import com.prabhix.identity.user.IdentityUserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The parts of phone sign-in that are security properties rather than plumbing.
 *
 * <p>A phone number is a weaker identifier than it appears — carriers recycle them, and SIM swap makes
 * one attacker-reachable — so the rules about what a number alone can do are the interesting content
 * here, not the Twilio call.
 */
class PhoneAuthServiceTest {

    private IdentityUserRepository users;
    private CredentialService credentials;
    private ChallengeService challenges;
    private SignInService signIn;
    private SmsSender sms;
    private PhoneAuthService service;

    @BeforeEach
    void setUp() {
        users = mock(IdentityUserRepository.class);
        credentials = mock(CredentialService.class);
        challenges = mock(ChallengeService.class);
        signIn = mock(SignInService.class);
        sms = mock(SmsSender.class);
        when(sms.enabled()).thenReturn(true);
        when(challenges.expiryMinutes()).thenReturn(10L);
        service = new PhoneAuthService(users, credentials, challenges, signIn, sms);
    }

    @Test
    @DisplayName("an unverified number is not a way in")
    void unverifiedNumberCannotSignIn() {
        // The repository method filters on phone_verified_at, so an account that merely has the number
        // typed into it is not found. Without that, anyone could sign in as somebody else by entering
        // their number — the verification step is the whole difference between a factor and a claim.
        when(users.findByPhoneAndPhoneVerifiedAtIsNotNullAndDeletedAtIsNull("+919876543210"))
                .thenReturn(Optional.empty());

        service.requestOtp("+919876543210", "1.2.3.4");

        verify(sms, never()).send(anyString(), anyString());
    }

    @Test
    @DisplayName("an unknown number sends no message at all, because every SMS costs money")
    void unknownNumberSendsNothing() {
        when(users.findByPhoneAndPhoneVerifiedAtIsNotNullAndDeletedAtIsNull(anyString()))
                .thenReturn(Optional.empty());

        var ack = service.requestOtp("+919999999999", "1.2.3.4");

        // The acknowledgement is the same either way, so this does not answer "does this number have
        // an account" — but nothing is actually sent, unlike the email flows where the cost of a wrong
        // guess is one unwanted message rather than one paid message.
        assertThat(ack.message()).contains("If that number has an account");
        verify(sms, never()).send(anyString(), anyString());
        verify(challenges, never()).raise(any(), any(), anyString(), anyString());
    }

    @Test
    @DisplayName("separators are stripped so one number is not two rows")
    void numberIsNormalized() {
        IdentityUser user = user();
        when(users.findByPhoneAndPhoneVerifiedAtIsNotNullAndDeletedAtIsNull("+919876543210"))
                .thenReturn(Optional.of(user));
        when(challenges.raise(any(), any(), anyString(), anyString()))
                .thenReturn(new ChallengeService.Raised(new AuthChallenge(), "123456"));

        service.requestOtp("+91 98765-43210", "1.2.3.4");

        // The challenge is looked up by destination string, so a number stored one way and submitted
        // another would raise a code that verification could never find.
        verify(sms).send(eq("+919876543210"), anyString());
    }

    @Test
    @DisplayName("a number with no country code is refused rather than guessed at")
    void nationalFormatIsRefused() {
        // Guessing +91 would silently send a code to a number in the wrong country, which looks
        // identical to a delivery failure from the caller's side.
        assertThatThrownBy(() -> service.requestOtp("9876543210", "1.2.3.4"))
                .isInstanceOf(ApiException.class)
                .extracting(ex -> ((ApiException) ex).getCode())
                .isEqualTo(ErrorCode.MALFORMED_REQUEST);
    }

    @Test
    @DisplayName("the phone flows refuse outright when no provider is configured")
    void refusesWhenSmsIsDisabled() {
        when(sms.enabled()).thenReturn(false);

        // Refused, not silently accepted. A 200 with no message delivered is the shape of bug that
        // reaches production and is reported as "OTP login is broken" with nothing in the logs.
        assertThatThrownBy(() -> service.requestOtp("+919876543210", "1.2.3.4"))
                .isInstanceOf(ApiException.class)
                .extracting(ex -> ((ApiException) ex).getCode())
                .isEqualTo(ErrorCode.FEATURE_DISABLED);
    }

    @Test
    @DisplayName("a number already verified elsewhere cannot be taken over")
    void verifiedNumberCannotBeReassigned() {
        IdentityUser other = user();
        when(users.findByPhoneAndPhoneVerifiedAtIsNotNullAndDeletedAtIsNull("+919876543210"))
                .thenReturn(Optional.of(other));

        // Silently moving it would let anyone claim somebody else's second factor by typing it, and
        // the victim would discover it at their next sign-in.
        assertThatThrownBy(() ->
                service.requestVerification(UUID.randomUUID(), "+919876543210", "1.2.3.4"))
                .isInstanceOf(ApiException.class)
                .extracting(ex -> ((ApiException) ex).getCode())
                .isEqualTo(ErrorCode.CONFLICT);
    }

    @Test
    @DisplayName("a code raised for one account cannot bind a number to another")
    void confirmationChecksTheChallengeBelongsToTheCaller() {
        UUID caller = UUID.randomUUID();
        AuthChallenge challenge = new AuthChallenge();
        challenge.setUserId(UUID.randomUUID());
        when(challenges.consumeByCode(eq("+919876543210"), eq("123456"), any()))
                .thenReturn(challenge);

        assertThatThrownBy(() -> service.confirmVerification(caller, "+919876543210", "123456"))
                .isInstanceOf(ApiException.class)
                .extracting(ex -> ((ApiException) ex).getCode())
                .isEqualTo(ErrorCode.OTP_INVALID);
    }

    @Test
    @DisplayName("a successful confirmation marks the number verified, not merely stored")
    void confirmationMarksVerified() {
        UUID caller = UUID.randomUUID();
        IdentityUser user = user();
        user.setId(caller);
        AuthChallenge challenge = new AuthChallenge();
        challenge.setUserId(caller);
        when(challenges.consumeByCode(anyString(), anyString(), any())).thenReturn(challenge);
        when(credentials.requireActive(caller)).thenReturn(user);

        service.confirmVerification(caller, "+919876543210", "123456");

        assertThat(user.getPhone()).isEqualTo("+919876543210");
        assertThat(user.getPhoneVerifiedAt()).isNotNull();
        verify(users).save(user);
    }

    @Test
    @DisplayName("signing in by SMS records how it happened")
    void signInRecordsTheMethod() {
        IdentityUser user = user();
        AuthChallenge challenge = new AuthChallenge();
        challenge.setUserId(user.getId());
        when(challenges.consumeByCode(anyString(), anyString(), any())).thenReturn(challenge);
        when(credentials.requireActive(user.getId())).thenReturn(user);

        service.verifyOtp("+919876543210", "123456", null);

        // amr ends up in the token, so a product can decline to act on a request authenticated by a
        // factor it does not consider strong enough for that action.
        verify(signIn).complete(eq(user), any(), eq(List.of("sms")));
    }

    private IdentityUser user() {
        IdentityUser user = new IdentityUser();
        user.setId(UUID.randomUUID());
        user.setEmail("phone@prabhixtechnologies.com");
        user.setFullName("Phone User");
        user.setPhone("+919876543210");
        user.setPhoneVerifiedAt(Instant.now());
        return user;
    }
}
