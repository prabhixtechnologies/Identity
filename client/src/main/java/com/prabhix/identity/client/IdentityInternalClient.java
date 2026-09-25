package com.prabhix.identity.client;

import com.prabhix.identity.client.IdentityAdmin.Actor;
import com.prabhix.identity.client.IdentityAdmin.AuthEvent;
import com.prabhix.identity.client.IdentityAdmin.ClientSummary;
import com.prabhix.identity.client.IdentityAdmin.EventQuery;
import com.prabhix.identity.client.IdentityAdmin.KeySummary;
import com.prabhix.identity.client.IdentityAdmin.Page;
import com.prabhix.identity.client.IdentityAdmin.UserAction;
import com.prabhix.identity.client.IdentityAdmin.UserDetail;
import com.prabhix.identity.client.IdentityAdmin.UserSearch;
import com.prabhix.identity.client.IdentityAdmin.UserSummary;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatusCode;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriBuilder;

import java.net.URI;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;

/**
 * Identity's private API, over the shared service token.
 *
 * <p>Two families of call. The first — {@link #lookup} and {@link #revokeTokens} — is what any
 * product needs to keep its user mirror and to act on a compromised account. The second, under
 * {@code /internal/admin}, is platform administration, and every call in it names the staff member
 * it is being made for, because identity records that person and not the calling service.
 *
 * <p>Fails closed: with no URL or no token configured nothing is sent, and the caller gets
 * {@link IdentityClientException.Kind#DISABLED} rather than a request with a blank header.
 */
public class IdentityInternalClient {

    public static final String SERVICE_TOKEN_HEADER = "X-Prabhix-Service-Token";
    public static final String ACTING_USER_HEADER = "X-Prabhix-Acting-User";
    public static final String ACTING_REASON_HEADER = "X-Prabhix-Acting-Reason";

    private static final Logger log = LoggerFactory.getLogger(IdentityInternalClient.class);

    private final IdentityClientProperties config;
    private final RestClient http;

    public IdentityInternalClient(IdentityClientProperties config, RestClient http) {
        this.config = config;
        this.http = http;
    }

    public boolean enabled() {
        return config.canCallInternal();
    }

    // ------------------------------------------------------------------ mirror and break-glass

    /** Users identity knows by id or by address. Deleted accounts are not returned. */
    public List<IdentityUser> lookup(List<UUID> ids, List<String> emails) {
        LookupResponse response = call("lookup", spec -> spec
                .post()
                .uri(config.internalBaseUrl() + "/internal/identity/users/lookup")
                .headers(h -> h.set(SERVICE_TOKEN_HEADER, config.serviceToken()))
                .body(new LookupRequest(ids == null ? List.of() : ids, emails == null ? List.of() : emails))
                .retrieve()
                .body(LookupResponse.class));
        return response == null || response.users() == null ? List.of() : response.users();
    }

    /** Every token for a user, whatever session minted it. */
    public void revokeTokens(UUID userId) {
        call("revokeTokens", spec -> spec
                .post()
                .uri(config.internalBaseUrl() + "/internal/identity/users/revoke-tokens?id=" + userId)
                .headers(h -> h.set(SERVICE_TOKEN_HEADER, config.serviceToken()))
                .retrieve()
                .toBodilessEntity());
    }

    // ------------------------------------------------------------------ admin, on a staff member's behalf

    public Page<UserSummary> searchUsers(UserSearch search, Actor actor) {
        return call("searchUsers", spec -> spec
                .get()
                .uri(uri -> admin(uri, "/users")
                        .queryParamIfPresent("q", opt(search.query()))
                        .queryParamIfPresent("status", opt(search.status()))
                        .queryParamIfPresent("cursor", opt(search.cursor()))
                        .queryParamIfPresent("limit", opt(search.limit()))
                        .build())
                .headers(h -> actorHeaders(h, actor))
                .retrieve()
                .body(new ParameterizedTypeReference<Page<UserSummary>>() { }));
    }

    public UserDetail getUser(UUID userId, Actor actor) {
        return call("getUser", spec -> spec
                .get()
                .uri(uri -> admin(uri, "/users").queryParam("id", userId).build())
                .headers(h -> actorHeaders(h, actor))
                .retrieve()
                .body(UserDetail.class));
    }

    public void disableUser(UUID userId, Actor actor) {
        userAction(userId, "disable", actor);
    }

    public void enableUser(UUID userId, Actor actor) {
        userAction(userId, "enable", actor);
    }

    public void unlockUser(UUID userId, Actor actor) {
        userAction(userId, "unlock", actor);
    }

    /** Invalidates the password and sends a reset link; nothing is returned to the caller. */
    public void forcePasswordReset(UUID userId, Actor actor) {
        userAction(userId, "force-reset", actor);
    }

    public void revokeSessions(UUID userId, Actor actor) {
        userAction(userId, "revoke-sessions", actor);
    }

    public List<ClientSummary> clients(Actor actor) {
        List<ClientSummary> result = call("clients", spec -> spec
                .get()
                .uri(uri -> admin(uri, "/clients").build())
                .headers(h -> actorHeaders(h, actor))
                .retrieve()
                .body(new ParameterizedTypeReference<List<ClientSummary>>() { }));
        return result == null ? List.of() : result;
    }

    public List<KeySummary> keys(Actor actor) {
        List<KeySummary> result = call("keys", spec -> spec
                .get()
                .uri(uri -> admin(uri, "/keys").build())
                .headers(h -> actorHeaders(h, actor))
                .retrieve()
                .body(new ParameterizedTypeReference<List<KeySummary>>() { }));
        return result == null ? List.of() : result;
    }

    public Page<AuthEvent> events(EventQuery query, Actor actor) {
        return call("events", spec -> spec
                .get()
                .uri(uri -> admin(uri, "/events")
                        .queryParamIfPresent("userId", opt(query.userId()))
                        .queryParamIfPresent("type", opt(query.type()))
                        .queryParamIfPresent("since", opt(query.since()))
                        .queryParamIfPresent("cursor", opt(query.cursor()))
                        .queryParamIfPresent("limit", opt(query.limit()))
                        .build())
                .headers(h -> actorHeaders(h, actor))
                .retrieve()
                .body(new ParameterizedTypeReference<Page<AuthEvent>>() { }));
    }

    // ------------------------------------------------------------------ plumbing

    private void userAction(UUID userId, String action, Actor actor) {
        call(action, spec -> spec
                .post()
                .uri(uri -> admin(uri, "/users/" + action).queryParam("id", userId).build())
                .headers(h -> actorHeaders(h, actor))
                .body(new UserAction(actor == null ? null : actor.reason()))
                .retrieve()
                .toBodilessEntity());
    }

    private UriBuilder admin(UriBuilder builder, String path) {
        URI base = URI.create(config.internalBaseUrl() + "/internal/identity/admin" + path);
        return builder.scheme(base.getScheme()).host(base.getHost()).port(base.getPort()).path(base.getPath());
    }

    private void actorHeaders(org.springframework.http.HttpHeaders headers, Actor actor) {
        headers.set(SERVICE_TOKEN_HEADER, config.serviceToken());
        if (actor == null || actor.userId() == null) {
            throw new IdentityClientException(IdentityClientException.Kind.REJECTED,
                    "An admin call must name the acting user");
        }
        headers.set(ACTING_USER_HEADER, actor.userId().toString());
        if (actor.reason() != null && !actor.reason().isBlank()) {
            headers.set(ACTING_REASON_HEADER, actor.reason());
        }
    }

    private static <T> java.util.Optional<T> opt(T value) {
        return java.util.Optional.ofNullable(value);
    }

    private <T> T call(String what, Function<RestClient, T> request) {
        if (!enabled()) {
            throw new IdentityClientException(IdentityClientException.Kind.DISABLED,
                    "This deployment cannot call identity: no internal URL or service token is configured");
        }
        try {
            return request.apply(http);
        } catch (HttpClientErrorException ex) {
            HttpStatusCode status = ex.getStatusCode();
            if (status.value() == 404) {
                throw new IdentityClientException(IdentityClientException.Kind.NOT_FOUND,
                        "Identity does not know that " + what.replace("get", "").toLowerCase(), ex);
            }
            log.warn("Identity refused {}: {} {}", what, status.value(), ex.getResponseBodyAsString());
            throw new IdentityClientException(IdentityClientException.Kind.REJECTED,
                    "Identity refused the request (" + status.value() + ")", ex);
        } catch (HttpServerErrorException | ResourceAccessException ex) {
            log.error("Identity unavailable for {}: {}", what, ex.getMessage());
            throw new IdentityClientException(IdentityClientException.Kind.UNAVAILABLE,
                    "Identity could not be reached. Try again.", ex);
        }
    }

    record LookupRequest(List<UUID> ids, List<String> emails) {
    }

    record LookupResponse(List<IdentityUser> users) {
    }
}
