package id.ac.ui.cs.advprog.bidmartauthservice.service.provisioning;

import com.fasterxml.jackson.databind.ObjectMapper;
import id.ac.ui.cs.advprog.bidmartauthservice.model.AuthOutboxEvent;
import id.ac.ui.cs.advprog.bidmartauthservice.model.AuthOutboxEventStatus;
import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.AuthOutboxEventRepository;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@Tag("unit")
class WalletProvisioningOutboxServiceTest {

    @Mock
    private AuthOutboxEventRepository authOutboxEventRepository;

    @Test
    void enqueueWalletProvisionRequestedShouldPersistPendingOutboxEvent() {
        WalletProvisioningEventMapper mapper = new WalletProvisioningEventMapper(new ObjectMapper().findAndRegisterModules());
        ReflectionTestUtils.setField(mapper, "source", "bidmart-auth-service");

        WalletProvisioningOutboxService outboxService = new WalletProvisioningOutboxService(
                authOutboxEventRepository,
                mapper
        );

        User user = User.builder()
                .id(UUID.randomUUID())
                .email("wallet@test.com")
                .build();

        outboxService.enqueueWalletProvisionRequested(user);

        ArgumentCaptor<AuthOutboxEvent> eventCaptor = ArgumentCaptor.forClass(AuthOutboxEvent.class);
        verify(authOutboxEventRepository).save(eventCaptor.capture());
        AuthOutboxEvent savedEvent = eventCaptor.getValue();

        WalletProvisionRequestedEvent payload = mapper.readPayload(savedEvent.getPayload());
        assertEquals(payload.eventId(), savedEvent.getId());
        assertEquals("USER", savedEvent.getAggregateType());
        assertEquals(user.getId(), savedEvent.getAggregateId());
        assertEquals(WalletProvisionRequestedEvent.EVENT_TYPE, savedEvent.getEventType());
        assertEquals(AuthOutboxEventStatus.PENDING, savedEvent.getStatus());
        assertEquals(0, savedEvent.getAttemptCount());
        assertNotNull(savedEvent.getCreatedAt());
        assertNotNull(savedEvent.getNextAttemptAt());
    }
}
