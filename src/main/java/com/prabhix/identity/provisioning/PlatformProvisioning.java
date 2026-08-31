package com.prabhix.identity.provisioning;

import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.config.IdentityProperties;
import com.prabhix.identity.user.IdentityUser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.UUID;

/**
 * Asks the platform for the organization half of a signup.
 *
 * <p>This service owns accounts and knows nothing about organizations — no trial window, no owner
 * membership, no seat limit, no subscription. The platform owns all of it, and duplicating any of it
 * here would mean two implementations of what a new tenant is, which is the kind of pair that agrees
 * on the day it is written and never again.
 *
 * <p>The only outbound call to a product in this service, and it is made while a person waits on a
 * signup form, so it fails loudly rather than in the background. A signup that produced an account
 * with no organization would look like it worked and then show an empty console with no way forward,
 * and the person cannot retry — the address is taken by then.
 */
@Slf4j
@Service
public class PlatformProvisioning {

    private final IdentityProperties properties;
    private final RestClient http;

    public PlatformProvisioning(IdentityProperties properties, RestClient.Builder httpBuilder) {
        this.properties = properties;
        this.http = httpBuilder.build();
    }

    /** Whether this deployment can provision at all: no shared token, no call. */
    public boolean configured() {
        String token = properties.serviceToken();
        return token != null && !token.isBlank();
    }

    /**
     * @return the organization the platform created, or the one this person already owned
     * @throws ApiException if the platform cannot be reached or refuses. The caller must undo the
     *     account it created, because there is nothing a person can do with half of a signup.
     */
    public UUID createOrganization(IdentityUser user, String organizationName) {
        if (!configured()) {
            throw ApiException.of(ErrorCode.FEATURE_DISABLED,
                    "Creating an organization is not available on this deployment");
        }

        ProvisionResponse response;
        try {
            response = http.post()
                    .uri(properties.platform().internalBaseUrl() + "/internal/organizations")
                    .header("X-Prabhix-Service-Token", properties.serviceToken())
                    .body(new ProvisionRequest(user.getId(), user.getEmail(), user.isEmailVerified(),
                            displayName(user), organizationName))
                    .retrieve()
                    .body(ProvisionResponse.class);
        } catch (RuntimeException ex) {
            // Deliberately not passing the platform's message through. It is written for us, not for
            // whoever is signing up, and at this point the useful thing to say is that it did not work
            // and their address is still free.
            log.error("Could not provision an organization for {}: {}", user.getId(), ex.getMessage());
            throw ApiException.of(ErrorCode.INTERNAL_ERROR,
                    "We could not finish setting up your workspace. Nothing was saved — please try again.");
        }

        if (response == null || response.organizationId() == null) {
            log.error("The platform accepted provisioning for {} and named no organization", user.getId());
            throw ApiException.of(ErrorCode.INTERNAL_ERROR,
                    "We could not finish setting up your workspace. Nothing was saved — please try again.");
        }

        log.info("Provisioned organization {} for {} (created={})",
                response.organizationId(), user.getId(), response.created());
        return response.organizationId();
    }

    /** {@code full_name} is required over there and optional here, so the address stands in for it. */
    private static String displayName(IdentityUser user) {
        if (user.getFullName() != null && !user.getFullName().isBlank()) {
            return user.getFullName();
        }
        return user.getEmail();
    }

    private record ProvisionRequest(UUID userId,
                                    String email,
                                    boolean emailVerified,
                                    String fullName,
                                    String organizationName) {
    }

    private record ProvisionResponse(UUID organizationId, boolean created) {
    }
}
