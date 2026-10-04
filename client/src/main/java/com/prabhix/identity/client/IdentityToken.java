package com.prabhix.identity.client;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * A verified Prabhix Identity access token.
 *
 * <p>States who the caller is and nothing about what they may do. There is no organization, shop,
 * role or permission here by design: authority is resolved by each product from its own database on
 * every request, so a claim in a token can never be the source of it.
 *
 * @param subject the identity user id — the key every product mirror uses
 * @param email the address at the time of issue; a mirror refresh, not this, is the current one
 * @param name the display name at the time of issue
 * @param emailVerified whether identity had verified the address
 * @param sessionId the {@code sid} claim — the identity session that minted this token, or null
 * @param tokenId the {@code jti}, for a per-token deny list
 * @param issuedAt the {@code iat}; second precision
 * @param expiresAt the {@code exp}
 * @param authenticationMethods the {@code amr} values, e.g. {@code pwd}, {@code otp}, {@code hwk}
 * @param claims every claim, for anything a product needs that is not modelled above
 */
public record IdentityToken(UUID subject,
                            String email,
                            String name,
                            boolean emailVerified,
                            UUID sessionId,
                            String tokenId,
                            Instant issuedAt,
                            Instant expiresAt,
                            List<String> authenticationMethods,
                            Map<String, Object> claims) {

    /** When the person last proved who they are. Absent on tokens issued before this claim existed. */
    public Instant authTime() {
        if (claims == null) {
            return null;
        }
        Object raw = claims.get("auth_time");
        if (raw instanceof Number number) {
            return Instant.ofEpochSecond(number.longValue());
        }
        if (raw instanceof String text && !text.isBlank()) {
            try {
                return Instant.ofEpochSecond(Long.parseLong(text.trim()));
            } catch (NumberFormatException ex) {
                return null;
            }
        }
        return null;
    }
}
