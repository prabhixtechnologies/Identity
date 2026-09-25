package com.prabhix.identity.web;

import com.prabhix.identity.event.AuthEventRecorder;
import com.prabhix.identity.event.AuthEventType;
import com.prabhix.identity.event.AuthEventType.Outcome;
import com.prabhix.identity.security.ServiceTokenAuthenticator;
import com.prabhix.identity.token.TokenDenyList;
import com.prabhix.identity.user.IdentityUser;
import com.prabhix.identity.user.IdentityUserRepository;
import com.prabhix.identity.web.AuthDtos.MirroredUser;
import com.prabhix.identity.web.AuthDtos.UserLookupRequest;
import com.prabhix.identity.web.AuthDtos.UserLookupResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static com.prabhix.identity.event.AuthEventRecorder.details;

/**
 * What a product calls to fill in its local mirror of the {@code users} table.
 *
 * <p>Every product keeps a thin {@code users} row keyed by the identity {@code sub}, because
 * twenty-one tables in the platform alone have a foreign key to it — {@code created_by},
 * {@code assignee_id}, {@code organization_memberships.user_id}. Those cannot point across a service
 * boundary, and rewriting them to hold an unenforced id would trade referential integrity for purity.
 *
 * <p>Pull rather than push, and on demand rather than on a schedule. A product discovers a user the
 * first time it sees a token naming one, which is precisely when it needs the row, and there is no
 * message bus to make a push reliable. The cost is a mirror that can be a few minutes stale on a name
 * change, which is the right thing to be wrong about.
 *
 * <p>Not routed publicly. Caddy does not expose {@code /internal}, and the shared token below is the
 * second lock rather than the only one.
 */
@RestController
@RequestMapping("/internal/identity")
@RequiredArgsConstructor
public class InternalUserController {

    private static final int MAX_BATCH = 200;

    private final IdentityUserRepository users;
    private final TokenDenyList denyList;
    private final ServiceTokenAuthenticator serviceTokens;
    private final AuthEventRecorder events;

    @PostMapping("/users/lookup")
    @Transactional(readOnly = true)
    public UserLookupResponse lookup(HttpServletRequest request,
                                     @RequestBody UserLookupRequest body) {
        serviceTokens.requireServiceToken(request);

        List<IdentityUser> found = new ArrayList<>();
        if (body.ids() != null && !body.ids().isEmpty()) {
            found.addAll(users.findByIdInAndDeletedAtIsNull(capped(body.ids())));
        }
        if (body.emails() != null && !body.emails().isEmpty()) {
            found.addAll(users.findActiveByEmails(capped(body.emails())));
        }

        return new UserLookupResponse(found.stream().distinct().map(this::toMirror).toList());
    }

    /**
     * Revokes every token for a user.
     *
     * <p>The break-glass path for "we believe this account is compromised". It has to work even when
     * the attacker is the one holding a valid session, which is why it is a service call rather than
     * something the account owner performs.
     *
     * <p>{@code X-Prabhix-Acting-User} is honoured when present but not required here, unlike on
     * {@code /internal/admin}: this route predates the header and products call it from automated
     * paths with no person behind them.
     */
    @PostMapping("/users/revoke-tokens")
    public void revokeTokens(HttpServletRequest request, @RequestParam UUID id) {
        serviceTokens.requireServiceToken(request);
        denyList.revokeUser(id);
        events.record(AuthEventType.TOKENS_REVOKED, Outcome.SUCCESS, id, null,
                serviceTokens.actingUser(request).orElse(null),
                details("route", "internal/users/revoke-tokens"));
    }

    private MirroredUser toMirror(IdentityUser user) {
        return new MirroredUser(
                user.getId(),
                user.getEmail(),
                user.isEmailVerified(),
                user.getFullName(),
                user.getDisplayName(),
                user.getAvatarUrl(),
                user.getJobTitle(),
                user.getTimezone(),
                user.getLocale(),
                user.getStatus().name(),
                user.isPlatformAdmin(),
                user.getUpdatedAt());
    }

    private <T> List<T> capped(List<T> values) {
        return values.size() <= MAX_BATCH ? values : values.subList(0, MAX_BATCH);
    }
}
