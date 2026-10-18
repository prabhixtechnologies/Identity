package com.prabhix.identity.provisioning;

import com.prabhix.identity.config.IdentityProperties;
import com.prabhix.identity.mail.AuthMailer;
import com.prabhix.identity.provisioning.PendingSignupStore.Draft;
import com.prabhix.identity.provisioning.PendingSignupStore.Issued;
import com.prabhix.identity.user.CredentialService;
import com.prabhix.identity.user.IdentityUser;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Email ownership gate that keeps a signup out of the database until the code is entered.
 *
 * <p>The form's details live in Redis for the challenge TTL. A matching code is what inserts the
 * account, and only then is a workspace provisioned.
 */
@Service
@RequiredArgsConstructor
public class SignupVerificationService {

    private final PendingSignupStore pending;
    private final CredentialService credentials;
    private final SignupService signup;
    private final AuthMailer mailer;
    private final IdentityProperties properties;

    /** Stores the signup and sends the code. Returns the token the session must keep. */
    public String begin(String email, String password, String fullName, String organizationName) {
        credentials.requireEmailAvailable(email);
        Issued issued = pending.begin(email, fullName, organizationName, credentials.hashPassword(password));
        try {
            mailer.sendSignupOtp(issued.email(), issued.name(), issued.code(), expiryMinutes());
        } catch (RuntimeException ex) {
            try {
                pending.discard(issued.token());
            } catch (RuntimeException cleanup) {
                ex.addSuppressed(cleanup);
            }
            throw ex;
        }
        return issued.token();
    }

    /** Address waiting on this token, or null when the hold has expired. */
    public String address(String token) {
        return pending.address(token);
    }

    public void resend(String token) {
        Issued issued = pending.resend(token);
        mailer.sendSignupOtp(issued.email(), issued.name(), issued.code(), expiryMinutes());
    }

    /** Creates the account after the code matches, then provisions a workspace when one was named. */
    public IdentityUser confirm(String token, String code) {
        Draft draft = pending.match(token, code);
        IdentityUser user = credentials.createVerified(draft.email(), draft.passwordHash(), draft.name());
        pending.discard(token);
        return signup.provision(user, draft.organization());
    }

    private long expiryMinutes() {
        return properties.challenge().ttl().toMinutes();
    }
}
