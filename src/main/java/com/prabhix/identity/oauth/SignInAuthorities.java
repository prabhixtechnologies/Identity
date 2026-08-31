package com.prabhix.identity.oauth;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.time.Instant;
import java.util.List;

/**
 * What a signed-in browser session carries, for every method the hosted page offers.
 *
 * <p>Two authorities, and the second is not decoration. Spring Security stamps each authentication
 * with a {@link FactorGrantedAuthority} recording which proof was given and when, and the
 * authorization server reads an ID token's {@code auth_time} claim back out of it. An authentication
 * assembled by hand without one mints no ID token at all — {@code JwtGenerator} asserts on it, so
 * {@code /oauth2/token} answers 500 *after* an otherwise perfect sign-in, which is a confusing place
 * for a failure to appear. Both places that build an authentication here go through this method so
 * neither can forget.
 *
 * <p>The factor named is the one that actually happened rather than a single constant, because that
 * is what the claim means: a relying party is entitled to know whether it is trusting a password or
 * a link someone clicked in their mail. It is also the only honest basis for a policy that one day
 * asks for a second factor — one that cannot tell the factors apart cannot require two of them.
 */
final class SignInAuthorities {

    private SignInAuthorities() {
    }

    /**
     * @param factor one of the {@code FactorGrantedAuthority} constants, naming the proof just given.
     */
    static List<GrantedAuthority> forFactor(String factor) {
        return List.of(
                new SimpleGrantedAuthority("ROLE_USER"),
                // Now, not the account's last-login column: this is the moment the proof was given,
                // and a relying party asking for a fresh authentication is asking about this instant.
                FactorGrantedAuthority.withAuthority(factor).issuedAt(Instant.now()).build());
    }
}
