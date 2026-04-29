package id.ac.ui.cs.advprog.bidmartauthservice.service.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import id.ac.ui.cs.advprog.bidmartauthservice.model.AuthOutboxEvent;
import id.ac.ui.cs.advprog.bidmartauthservice.model.AuthOutboxEventStatus;
import id.ac.ui.cs.advprog.bidmartauthservice.model.Permission;
import id.ac.ui.cs.advprog.bidmartauthservice.model.RefreshToken;
import id.ac.ui.cs.advprog.bidmartauthservice.model.Role;
import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.AuthOutboxEventRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthAuditOutboxService {

    private static final String AGGREGATE_USER = "USER";
    private static final String AGGREGATE_ROLE = "ROLE";
    private static final String AGGREGATE_SESSION = "SESSION";

    public static final String EVENT_ROLE_CREATED = "RoleCreated";
    public static final String EVENT_USER_ROLE_CHANGED = "UserRoleChanged";
    public static final String EVENT_USER_DISABLED = "UserDisabled";
    public static final String EVENT_SESSION_REVOKED = "SessionRevoked";

    private final AuthOutboxEventRepository authOutboxEventRepository;
    private final ObjectMapper objectMapper;

    @Transactional
    public void enqueueRoleCreated(Role role) {
        Instant now = Instant.now();
        List<String> permissions = role.getPermissions() == null
                ? List.of()
                : role.getPermissions().stream()
                .map(Permission::getName)
                .sorted()
                .toList();

        saveEvent(
                AGGREGATE_ROLE,
                role.getId(),
                EVENT_ROLE_CREATED,
                Map.of(
                        "roleId", role.getId(),
                        "roleName", role.getName(),
                        "permissions", permissions,
                        "occurredAt", now.toString()
                ),
                now
        );
    }

    @Transactional
    public void enqueueUserRoleChanged(User user, Role assignedRole) {
        Instant now = Instant.now();
        saveEvent(
                AGGREGATE_USER,
                user.getId(),
                EVENT_USER_ROLE_CHANGED,
                Map.of(
                        "userId", user.getId(),
                        "email", user.getEmail(),
                        "roleId", assignedRole.getId(),
                        "roleName", assignedRole.getName(),
                        "occurredAt", now.toString()
                ),
                now
        );
    }

    @Transactional
    public void enqueueUserDisabled(User user) {
        Instant now = Instant.now();
        saveEvent(
                AGGREGATE_USER,
                user.getId(),
                EVENT_USER_DISABLED,
                Map.of(
                        "userId", user.getId(),
                        "email", user.getEmail(),
                        "occurredAt", now.toString()
                ),
                now
        );
    }

    @Transactional
    public void enqueueSessionRevoked(RefreshToken refreshToken) {
        Instant now = Instant.now();
        User user = refreshToken.getUser();
        saveEvent(
                AGGREGATE_SESSION,
                refreshToken.getTokenId(),
                EVENT_SESSION_REVOKED,
                Map.of(
                        "sessionId", refreshToken.getTokenId(),
                        "userId", user.getId(),
                        "email", user.getEmail(),
                        "occurredAt", now.toString()
                ),
                now
        );
    }

    private void saveEvent(String aggregateType, UUID aggregateId, String eventType, Map<String, Object> payload, Instant now) {
        AuthOutboxEvent outboxEvent = AuthOutboxEvent.builder()
                .id(UUID.randomUUID())
                .aggregateType(aggregateType)
                .aggregateId(aggregateId)
                .eventType(eventType)
                .payload(writePayload(payload))
                .status(AuthOutboxEventStatus.PENDING)
                .attemptCount(0)
                .nextAttemptAt(now)
                .createdAt(now)
                .build();

        authOutboxEventRepository.save(outboxEvent);
    }

    private String writePayload(Map<String, Object> payload) {
        try {
            return objectMapper.writeValueAsString(payload);
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("Unable to serialize auth audit event", exception);
        }
    }
}
