package id.ac.ui.cs.advprog.bidmartauthservice.service.provisioning;

import id.ac.ui.cs.advprog.bidmartauthservice.model.AuthOutboxEvent;
import id.ac.ui.cs.advprog.bidmartauthservice.model.AuthOutboxEventStatus;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.AuthOutboxEventRepository;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@Tag("unit")
class WalletProvisioningOutboxPublisherTest {

    @Mock
    private AuthOutboxEventRepository authOutboxEventRepository;

    @Mock
    private WalletProvisioningEventMapper walletProvisioningEventMapper;

    @Mock
    private WalletProvisioningMessagePublisher walletProvisioningMessagePublisher;

    @Test
    void publishPendingEventsAtShouldPublishAndMarkEventAsPublished() {
        WalletProvisioningOutboxPublisher publisher = new WalletProvisioningOutboxPublisher(
                authOutboxEventRepository,
                walletProvisioningEventMapper,
                walletProvisioningMessagePublisher
        );
        ReflectionTestUtils.setField(publisher, "batchSize", 50);
        ReflectionTestUtils.setField(publisher, "maxAttempts", 10);
        ReflectionTestUtils.setField(publisher, "retryBaseSeconds", 30L);
        ReflectionTestUtils.setField(publisher, "retryMaxSeconds", 900L);

        Instant now = Instant.parse("2026-04-16T13:00:00Z");
        AuthOutboxEvent outboxEvent = AuthOutboxEvent.builder()
                .id(UUID.randomUUID())
                .status(AuthOutboxEventStatus.PENDING)
                .attemptCount(0)
                .payload("{\"eventId\":\"x\"}")
                .createdAt(now.minusSeconds(30))
                .nextAttemptAt(now.minusSeconds(1))
                .build();
        WalletProvisionRequestedEvent payload = new WalletProvisionRequestedEvent(
                UUID.randomUUID(),
                UUID.randomUUID(),
                "wallet@test.com",
                now.minusSeconds(10),
                "bidmart-auth-service"
        );

        when(authOutboxEventRepository.findReadyForPublish(any(), eq(now), any())).thenReturn(List.of(outboxEvent));
        when(walletProvisioningEventMapper.readPayload(outboxEvent.getPayload())).thenReturn(payload);

        publisher.publishPendingEventsAt(now);

        verify(walletProvisioningMessagePublisher).publish(payload);
        verify(authOutboxEventRepository).save(outboxEvent);
        assertEquals(AuthOutboxEventStatus.PUBLISHED, outboxEvent.getStatus());
        assertEquals(1, outboxEvent.getAttemptCount());
        assertEquals(now, outboxEvent.getPublishedAt());
    }

    @Test
    void publishPendingEventsAtShouldMoveEventToRetryWhenPublishFails() {
        WalletProvisioningOutboxPublisher publisher = new WalletProvisioningOutboxPublisher(
                authOutboxEventRepository,
                walletProvisioningEventMapper,
                walletProvisioningMessagePublisher
        );
        ReflectionTestUtils.setField(publisher, "batchSize", 50);
        ReflectionTestUtils.setField(publisher, "maxAttempts", 3);
        ReflectionTestUtils.setField(publisher, "retryBaseSeconds", 10L);
        ReflectionTestUtils.setField(publisher, "retryMaxSeconds", 120L);

        Instant now = Instant.parse("2026-04-16T13:00:00Z");
        AuthOutboxEvent outboxEvent = AuthOutboxEvent.builder()
                .id(UUID.randomUUID())
                .status(AuthOutboxEventStatus.PENDING)
                .attemptCount(0)
                .payload("{\"eventId\":\"x\"}")
                .createdAt(now.minusSeconds(30))
                .nextAttemptAt(now.minusSeconds(1))
                .build();
        WalletProvisionRequestedEvent payload = new WalletProvisionRequestedEvent(
                UUID.randomUUID(),
                UUID.randomUUID(),
                "wallet@test.com",
                now.minusSeconds(10),
                "bidmart-auth-service"
        );

        when(authOutboxEventRepository.findReadyForPublish(any(), eq(now), any())).thenReturn(List.of(outboxEvent));
        when(walletProvisioningEventMapper.readPayload(outboxEvent.getPayload())).thenReturn(payload);
        doThrow(new RuntimeException("broker unavailable")).when(walletProvisioningMessagePublisher).publish(payload);

        publisher.publishPendingEventsAt(now);

        verify(authOutboxEventRepository).save(outboxEvent);
        assertEquals(AuthOutboxEventStatus.RETRY, outboxEvent.getStatus());
        assertEquals(1, outboxEvent.getAttemptCount());
        assertEquals(now.plusSeconds(10), outboxEvent.getNextAttemptAt());
    }

    @Test
    void publishPendingEventsAtShouldMarkEventFailedWhenMaxAttemptsReached() {
        WalletProvisioningOutboxPublisher publisher = new WalletProvisioningOutboxPublisher(
                authOutboxEventRepository,
                walletProvisioningEventMapper,
                walletProvisioningMessagePublisher
        );
        ReflectionTestUtils.setField(publisher, "batchSize", 50);
        ReflectionTestUtils.setField(publisher, "maxAttempts", 2);
        ReflectionTestUtils.setField(publisher, "retryBaseSeconds", 10L);
        ReflectionTestUtils.setField(publisher, "retryMaxSeconds", 120L);

        Instant now = Instant.parse("2026-04-16T13:00:00Z");
        AuthOutboxEvent outboxEvent = AuthOutboxEvent.builder()
                .id(UUID.randomUUID())
                .status(AuthOutboxEventStatus.RETRY)
                .attemptCount(1)
                .payload("{\"eventId\":\"x\"}")
                .createdAt(now.minusSeconds(30))
                .nextAttemptAt(now.minusSeconds(1))
                .build();
        WalletProvisionRequestedEvent payload = new WalletProvisionRequestedEvent(
                UUID.randomUUID(),
                UUID.randomUUID(),
                "wallet@test.com",
                now.minusSeconds(10),
                "bidmart-auth-service"
        );

        when(authOutboxEventRepository.findReadyForPublish(any(), eq(now), any())).thenReturn(List.of(outboxEvent));
        when(walletProvisioningEventMapper.readPayload(outboxEvent.getPayload())).thenReturn(payload);
        doThrow(new RuntimeException("broker unavailable")).when(walletProvisioningMessagePublisher).publish(payload);

        publisher.publishPendingEventsAt(now);

        verify(authOutboxEventRepository).save(outboxEvent);
        assertEquals(AuthOutboxEventStatus.FAILED, outboxEvent.getStatus());
        assertEquals(2, outboxEvent.getAttemptCount());
        assertEquals(now, outboxEvent.getNextAttemptAt());
    }
}
