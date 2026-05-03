package id.ac.ui.cs.advprog.bidmartauthservice.service.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import id.ac.ui.cs.advprog.bidmartauthservice.model.AuthOutboxEvent;
import id.ac.ui.cs.advprog.bidmartauthservice.model.AuthOutboxEventStatus;
import id.ac.ui.cs.advprog.bidmartauthservice.model.Permission;
import id.ac.ui.cs.advprog.bidmartauthservice.model.RefreshToken;
import id.ac.ui.cs.advprog.bidmartauthservice.model.Role;
import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.AuthOutboxEventRepository;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@Tag("unit")
class AuthAuditOutboxServiceTest {

    private final AuthOutboxEventRepository repository = mock(AuthOutboxEventRepository.class);
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AuthAuditOutboxService service = new AuthAuditOutboxService(repository, objectMapper);

    @Test
    void enqueueRoleCreatedPersistsSortedPermissionPayload() throws Exception {
        Role role = Role.builder()
                .id(UUID.randomUUID())
                .name("seller")
                .permissions(Set.of(
                        Permission.builder().id(UUID.randomUUID()).name("wallet:view").build(),
                        Permission.builder().id(UUID.randomUUID()).name("auction:create").build()
                ))
                .build();

        when(repository.save(any(AuthOutboxEvent.class))).thenAnswer(invocation -> invocation.getArgument(0));

        service.enqueueRoleCreated(role);

        AuthOutboxEvent event = capturedEvent();
        JsonNode payload = objectMapper.readTree(event.getPayload());

        assertEquals("ROLE", event.getAggregateType());
        assertEquals(role.getId(), event.getAggregateId());
        assertEquals(AuthAuditOutboxService.EVENT_ROLE_CREATED, event.getEventType());
        assertEquals(AuthOutboxEventStatus.PENDING, event.getStatus());
        assertEquals(0, event.getAttemptCount());
        assertNotNull(event.getId());
        assertNotNull(event.getCreatedAt());
        assertNotNull(event.getNextAttemptAt());
        assertEquals("seller", payload.get("roleName").asText());
        assertEquals(List.of("auction:create", "wallet:view"), List.of(
                payload.get("permissions").get(0).asText(),
                payload.get("permissions").get(1).asText()
        ));
    }

    @Test
    void enqueueUserRoleChangedPersistsUserAndRolePayload() throws Exception {
        User user = user();
        Role role = Role.builder().id(UUID.randomUUID()).name("buyer").build();

        service.enqueueUserRoleChanged(user, role);

        AuthOutboxEvent event = capturedEvent();
        JsonNode payload = objectMapper.readTree(event.getPayload());

        assertEquals("USER", event.getAggregateType());
        assertEquals(user.getId(), event.getAggregateId());
        assertEquals(AuthAuditOutboxService.EVENT_USER_ROLE_CHANGED, event.getEventType());
        assertEquals(user.getEmail(), payload.get("email").asText());
        assertEquals(role.getId().toString(), payload.get("roleId").asText());
        assertEquals("buyer", payload.get("roleName").asText());
    }

    @Test
    void enqueueUserDisabledPersistsUserPayload() throws Exception {
        User user = user();

        service.enqueueUserDisabled(user);

        AuthOutboxEvent event = capturedEvent();
        JsonNode payload = objectMapper.readTree(event.getPayload());

        assertEquals("USER", event.getAggregateType());
        assertEquals(user.getId(), event.getAggregateId());
        assertEquals(AuthAuditOutboxService.EVENT_USER_DISABLED, event.getEventType());
        assertEquals(user.getId().toString(), payload.get("userId").asText());
        assertEquals(user.getEmail(), payload.get("email").asText());
    }

    @Test
    void enqueueSessionRevokedPersistsSessionPayload() throws Exception {
        User user = user();
        RefreshToken refreshToken = RefreshToken.builder()
                .id(UUID.randomUUID())
                .tokenId(UUID.randomUUID())
                .user(user)
                .expiresAt(Instant.now().plusSeconds(3600))
                .createdAt(Instant.now())
                .revoked(true)
                .build();

        service.enqueueSessionRevoked(refreshToken);

        AuthOutboxEvent event = capturedEvent();
        JsonNode payload = objectMapper.readTree(event.getPayload());

        assertEquals("SESSION", event.getAggregateType());
        assertEquals(refreshToken.getTokenId(), event.getAggregateId());
        assertEquals(AuthAuditOutboxService.EVENT_SESSION_REVOKED, event.getEventType());
        assertEquals(refreshToken.getTokenId().toString(), payload.get("sessionId").asText());
        assertEquals(user.getId().toString(), payload.get("userId").asText());
    }

    private AuthOutboxEvent capturedEvent() {
        ArgumentCaptor<AuthOutboxEvent> captor = ArgumentCaptor.forClass(AuthOutboxEvent.class);
        verify(repository).save(captor.capture());
        return captor.getValue();
    }

    private User user() {
        return User.builder()
                .id(UUID.randomUUID())
                .email("user@example.com")
                .password("password")
                .build();
    }
}
