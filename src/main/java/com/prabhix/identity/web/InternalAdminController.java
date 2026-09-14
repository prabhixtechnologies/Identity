package com.prabhix.identity.web;

import com.prabhix.identity.admin.InternalAdminService;
import com.prabhix.identity.security.ServiceTokenAuthenticator;
import com.prabhix.identity.security.ServiceTokenAuthenticator.Actor;
import com.prabhix.identity.web.AdminDtos.AuthEvent;
import com.prabhix.identity.web.AdminDtos.ClientSummary;
import com.prabhix.identity.web.AdminDtos.KeySummary;
import com.prabhix.identity.web.AdminDtos.Page;
import com.prabhix.identity.web.AdminDtos.UserAction;
import com.prabhix.identity.web.AdminDtos.UserDetail;
import com.prabhix.identity.web.AdminDtos.UserSummary;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Platform administration of identity, for a product acting on a staff member's behalf.
 *
 * <p>The service token authenticates the product; {@code X-Prabhix-Acting-User} names the person.
 * Both are required on every call, including the reads: an audit trail that cannot say who looked
 * is only slightly more useful than none, and the client always sends the header anyway.
 */
@RestController
@RequestMapping("/internal/admin")
@RequiredArgsConstructor
public class InternalAdminController {

    private final ServiceTokenAuthenticator serviceTokens;
    private final InternalAdminService admin;

    @GetMapping("/users")
    public Page<UserSummary> searchUsers(HttpServletRequest request,
                                         @RequestParam(required = false) String q,
                                         @RequestParam(required = false) String status,
                                         @RequestParam(required = false) String cursor,
                                         @RequestParam(required = false) Integer limit) {
        serviceTokens.requireActor(request);
        return admin.searchUsers(q, status, cursor, limit);
    }

    @GetMapping("/users/{id}")
    public UserDetail getUser(HttpServletRequest request, @PathVariable UUID id) {
        serviceTokens.requireActor(request);
        return admin.getUser(id);
    }

    @PostMapping("/users/{id}/disable")
    public void disable(HttpServletRequest request,
                        @PathVariable UUID id,
                        @RequestBody(required = false) UserAction body) {
        admin.disable(id, actor(request, body));
    }

    @PostMapping("/users/{id}/enable")
    public void enable(HttpServletRequest request,
                       @PathVariable UUID id,
                       @RequestBody(required = false) UserAction body) {
        admin.enable(id, actor(request, body));
    }

    @PostMapping("/users/{id}/unlock")
    public void unlock(HttpServletRequest request,
                       @PathVariable UUID id,
                       @RequestBody(required = false) UserAction body) {
        admin.unlock(id, actor(request, body));
    }

    @PostMapping("/users/{id}/force-reset")
    public void forceReset(HttpServletRequest request,
                           @PathVariable UUID id,
                           @RequestBody(required = false) UserAction body) {
        admin.forceReset(id, actor(request, body));
    }

    @PostMapping("/users/{id}/revoke-sessions")
    public void revokeSessions(HttpServletRequest request,
                               @PathVariable UUID id,
                               @RequestBody(required = false) UserAction body) {
        admin.revokeSessions(id, actor(request, body));
    }

    @GetMapping("/clients")
    public List<ClientSummary> clients(HttpServletRequest request) {
        serviceTokens.requireActor(request);
        return admin.clients();
    }

    @GetMapping("/keys")
    public List<KeySummary> keys(HttpServletRequest request) {
        serviceTokens.requireActor(request);
        return admin.keys();
    }

    @GetMapping("/events")
    public Page<AuthEvent> events(HttpServletRequest request,
                                  @RequestParam(required = false) UUID userId,
                                  @RequestParam(required = false) String type,
                                  @RequestParam(required = false) Instant since,
                                  @RequestParam(required = false) String cursor,
                                  @RequestParam(required = false) Integer limit) {
        serviceTokens.requireActor(request);
        return admin.events(userId, type, since, cursor, limit);
    }

    private Actor actor(HttpServletRequest request, UserAction body) {
        Actor header = serviceTokens.requireActor(request);
        if (header.reason() != null || body == null || body.reason() == null || body.reason().isBlank()) {
            return header;
        }
        return new Actor(header.userId(), body.reason().trim());
    }
}
