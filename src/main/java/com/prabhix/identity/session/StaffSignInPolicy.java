package com.prabhix.identity.session;

import com.prabhix.identity.user.IdentityUser;
import org.springframework.security.core.authority.FactorGrantedAuthority;

import java.util.List;
import java.util.Set;

/**
 * Staff accounts do not finish on a password alone.
 *
 * <p>A passkey or a one-time code is the second proof. Everyone else may still sign in with a
 * password; sensitive actions ask them to step up separately.
 */
public final class StaffSignInPolicy {

    private static final Set<String> ALLOWED = Set.of(
            FactorGrantedAuthority.WEBAUTHN_AUTHORITY,
            FactorGrantedAuthority.OTT_AUTHORITY,
            FactorGrantedAuthority.X509_AUTHORITY,
            "swk",
            "otp",
            "sms",
            "whatsapp");

    private StaffSignInPolicy() {
    }

    public static boolean allows(IdentityUser user, List<String> methods) {
        if (user == null || !user.isPlatformAdmin()) {
            return true;
        }
        if (methods == null) {
            return false;
        }
        return methods.stream().anyMatch(ALLOWED::contains);
    }
}
