package com.prabhix.identity.web;

import com.prabhix.identity.admin.InternalAdminService;
import com.prabhix.identity.common.ApiException;
import com.prabhix.identity.common.ErrorCode;
import com.prabhix.identity.security.ServiceTokenAuthenticator;
import com.prabhix.identity.security.ServiceTokenAuthenticator.Actor;
import com.prabhix.identity.web.AdminDtos.UserAction;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class InternalAdminControllerTest {

    private ServiceTokenAuthenticator serviceTokens;
    private InternalAdminService admin;
    private InternalAdminController controller;
    private HttpServletRequest request;

    @BeforeEach
    void setUp() {
        serviceTokens = mock(ServiceTokenAuthenticator.class);
        admin = mock(InternalAdminService.class);
        controller = new InternalAdminController(serviceTokens, admin);
        request = mock(HttpServletRequest.class);
    }

    @Test
    @DisplayName("disabling an account without an acting user is refused")
    void disableRequiresActor() {
        when(serviceTokens.requireActor(request)).thenThrow(ApiException.of(
                ErrorCode.ACTING_USER_REQUIRED,
                "X-Prabhix-Acting-User must carry the id of the staff member making this request"));

        UUID userId = UUID.randomUUID();
        assertThat(catchApi(() -> controller.disable(request, userId, new UserAction("compromise")))
                .getCode())
                .isEqualTo(ErrorCode.ACTING_USER_REQUIRED);
        verify(admin, never()).disable(any(), any());
    }

    @Test
    @DisplayName("disabling an account records the staff member who asked")
    void disablePassesActor() {
        UUID actorId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();
        Actor actor = new Actor(actorId, "compromise");
        when(serviceTokens.requireActor(request)).thenReturn(actor);

        controller.disable(request, userId, new UserAction("compromise"));

        verify(admin).disable(userId, actor);
    }

    private ApiException catchApi(Runnable action) {
        try {
            action.run();
        } catch (ApiException ex) {
            return ex;
        }
        throw new AssertionError("Expected an ApiException, but the call succeeded");
    }
}
