package com.prabhix.identity.challenge;

import com.prabhix.identity.challenge.AuthChallenge.ChallengePurpose;
import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.config.IdentityProperties;
import com.prabhix.identity.mail.AuthMailer;
import com.prabhix.identity.session.SessionService.DeviceContext;
import com.prabhix.identity.session.SignInService;
import com.prabhix.identity.user.CredentialService;
import com.prabhix.identity.user.IdentityUser;
import com.prabhix.identity.web.AuthDtos.AckResponse;
import com.prabhix.identity.web.AuthDtos.TokenResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

/** Signing in without a password: magic link and emailed OTP, plus password reset. */
@Service
@RequiredArgsConstructor
public class PasswordlessService {

    /**
     * The same answer whether or not the address has an account.
     *
     * <p>Anything else turns this endpoint into a membership oracle: ask it about an address and
     * learn whether that person is a customer.
     */
    private static final AckResponse GENERIC_ACK =
            new AckResponse("If that address is registered, you will receive an email shortly.");

    private final ChallengeService challenges;
    private final CredentialService credentials;
    private final SignInService signIn;
    private final AuthMailer mailer;
    private final IdentityProperties properties;

    @Transactional
    public AckResponse requestMagicLink(String email, String ipAddress) {
        Optional<IdentityUser> user = credentials.findByEmail(email);
        if (user.isPresent()) {
            ChallengeService.Raised raised = challenges.raise(
                    ChallengePurpose.MAGIC_LINK, user.get().getId(), user.get().getEmail(), ipAddress);
            mailer.sendMagicLink(
                    user.get().getEmail(),
                    user.get().effectiveDisplayName(),
                    hostedLink("/login/link", raised.rawSecret()),
                    challenges.expiryMinutes());
        }
        return GENERIC_ACK;
    }

    /**
     * Consumes a magic link and returns whose it was, issuing nothing.
     *
     * <p>Separate from {@link #verifyMagicLink} because the hosted login page needs the first half
     * and not the second: a browser in the middle of an authorization code flow wants a session
     * cookie, and the refresh token {@code SignInService.complete} also mints would be handed to
     * nobody and revoked by nothing.
     */
    @Transactional
    public IdentityUser authenticateByMagicLink(String rawToken) {
        AuthChallenge challenge = challenges.consumeBySecret(rawToken, ChallengePurpose.MAGIC_LINK);
        IdentityUser user = credentials.requireActive(challenge.getUserId());
        credentials.resetLoginFailures(user);
        // A magic link proves control of the mailbox, which is exactly what email verification
        // proves, so a first sign-in by link should not then ask the user to confirm the address.
        credentials.markEmailVerified(user.getId());
        return user;
    }

    @Transactional
    public TokenResponse verifyMagicLink(String rawToken, DeviceContext device) {
        return signIn.complete(authenticateByMagicLink(rawToken), device, List.of("link"));
    }

    @Transactional
    public AckResponse requestOtp(String email, String ipAddress) {
        Optional<IdentityUser> user = credentials.findByEmail(email);
        if (user.isPresent()) {
            ChallengeService.Raised raised = challenges.raise(
                    ChallengePurpose.EMAIL_OTP, user.get().getId(), user.get().getEmail(), ipAddress);
            mailer.sendOtp(user.get().getEmail(), raised.rawSecret(), challenges.expiryMinutes());
        }
        return GENERIC_ACK;
    }

    /** Consumes an emailed code and returns whose it was, issuing nothing. */
    @Transactional
    public IdentityUser authenticateByOtp(String email, String code) {
        AuthChallenge challenge = challenges.consumeByCode(email, code, ChallengePurpose.EMAIL_OTP);
        IdentityUser user = credentials.requireActive(challenge.getUserId());
        credentials.resetLoginFailures(user);
        credentials.markEmailVerified(user.getId());
        return user;
    }

    @Transactional
    public TokenResponse verifyOtp(String email, String code, DeviceContext device) {
        return signIn.complete(authenticateByOtp(email, code), device, List.of("otp"));
    }

    @Transactional
    public AckResponse requestPasswordReset(String email, String ipAddress) {
        Optional<IdentityUser> user = credentials.findByEmail(email);
        if (user.isPresent()) {
            ChallengeService.Raised raised = challenges.raise(
                    ChallengePurpose.PASSWORD_RESET, user.get().getId(), user.get().getEmail(), ipAddress);
            mailer.sendPasswordReset(
                    user.get().getEmail(),
                    user.get().effectiveDisplayName(),
                    consoleLink("/reset-password", raised.rawSecret()),
                    challenges.expiryMinutes());
        }
        return GENERIC_ACK;
    }

    @Transactional
    public AckResponse resetPassword(String rawToken, String newPassword) {
        AuthChallenge challenge = challenges.consumeBySecret(rawToken, ChallengePurpose.PASSWORD_RESET);
        if (challenge.getUserId() == null) {
            throw ApiException.of(ErrorCode.TOKEN_INVALID, "That link is not valid");
        }
        credentials.setPassword(challenge.getUserId(), newPassword);
        return new AckResponse("Your password has been updated.");
    }

    /**
     * Builds a link into the console's router, not the API.
     *
     * <p>These are console paths on purpose. The two drifted apart once before and every emailed
     * magic link 404'd, so the path is spelled the way {@code web/src/routes.tsx} spells it.
     */
    private String consoleLink(String path, String rawToken) {
        return properties.urls().console() + path + "?token="
                + URLEncoder.encode(rawToken, StandardCharsets.UTF_8);
    }

    /**
     * Builds a link back to this service's own hosted page.
     *
     * <p>A magic link has to land wherever the challenge it names can be found, and challenges are in
     * this service's database. Pointing it at the console meant the console posting the token to
     * {@code /api/v1/auth/magic-link/verify}, which the gateway routes by {@code AUTH_UPSTREAM} — so
     * before that cutover the token was looked for in the platform's database and never found. The
     * link was dead for exactly as long as the two halves disagreed.
     *
     * <p>Landing here also resumes the authorization request the person started, which a console page
     * cannot do: the session cookie belongs to this origin.
     */
    private String hostedLink(String path, String rawToken) {
        return properties.issuer() + path + "?token="
                + URLEncoder.encode(rawToken, StandardCharsets.UTF_8);
    }
}
