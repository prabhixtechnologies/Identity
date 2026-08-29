package com.prabhix.identity.token;

import java.util.List;
import java.util.UUID;

/**
 * What an identity token says, and nothing more.
 *
 * <p>Note what is absent: no organisation, no shop, no permissions. The platform's current access
 * token carries a {@code perms} array and MobiStack's carries its own set, and centralising both
 * here would make this service own two unrelated permission models — a change to a repair-shop
 * permission would need a release of the thing that signs everybody's tokens.
 *
 * <p>Each product resolves permissions per request from its own database instead. That is also
 * strictly more correct than today: permissions currently freeze into the token at sign-in, so a
 * revoked role keeps working until the access token expires.
 *
 * @param subject the stable user id, the {@code sub} claim; the only identifier products should
 *     store against their own rows
 * @param sessionId the {@code sid} claim, so a product can tell two concurrent sign-ins apart and
 *     this service can revoke one of them
 * @param authenticationMethods the {@code amr} claim, e.g. {@code pwd}, {@code otp}, {@code google}.
 *     A product that wants to require a stronger method for a sensitive action needs to know how
 *     this session was established, and cannot ask after the fact.
 */
public record IdentityClaims(
        UUID subject,
        String email,
        boolean emailVerified,
        String name,
        UUID sessionId,
        List<String> authenticationMethods) {
}
