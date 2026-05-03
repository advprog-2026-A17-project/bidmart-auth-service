package id.ac.ui.cs.advprog.bidmartauthservice.service.provisioning;

import id.ac.ui.cs.advprog.bidmartauthservice.model.AuthOutboxEvent;
import id.ac.ui.cs.advprog.bidmartauthservice.model.AuthOutboxEventStatus;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.AuthOutboxEventRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

@Component
@RequiredArgsConstructor
public class WalletProvisioningOutboxPublisher {

    private static final List<AuthOutboxEventStatus> RETRYABLE_STATUSES = List.of(
            AuthOutboxEventStatus.PENDING,
            AuthOutboxEventStatus.RETRY
    );

    private final AuthOutboxEventRepository authOutboxEventRepository;
    private final WalletProvisioningEventMapper walletProvisioningEventMapper;
    private final WalletProvisioningMessagePublisher walletProvisioningMessagePublisher;

    @Value("${app.auth.wallet-provisioning.outbox.batch-size:50}")
    private int batchSize;

    @Value("${app.auth.wallet-provisioning.outbox.max-attempts:10}")
    private int maxAttempts;

    @Value("${app.auth.wallet-provisioning.outbox.retry-base-seconds:30}")
    private long retryBaseSeconds;

    @Value("${app.auth.wallet-provisioning.outbox.retry-max-seconds:900}")
    private long retryMaxSeconds;

    @Scheduled(fixedDelayString = "${app.auth.wallet-provisioning.outbox.publish-delay-ms:5000}")
    @Transactional
    public void publishPendingEvents() {
        publishPendingEventsAt(Instant.now());
    }

    void publishPendingEventsAt(Instant now) {
        int effectiveBatchSize = batchSize > 0 ? batchSize : 50;
        int effectiveMaxAttempts = maxAttempts > 0 ? maxAttempts : 10;

        List<AuthOutboxEvent> pendingEvents = authOutboxEventRepository.findReadyForPublish(
                RETRYABLE_STATUSES,
                now,
                PageRequest.of(0, effectiveBatchSize)
        );

        for (AuthOutboxEvent pendingEvent : pendingEvents) {
            try {
                WalletProvisionRequestedEvent payload = walletProvisioningEventMapper.readPayload(pendingEvent.getPayload());
                walletProvisioningMessagePublisher.publish(payload);
                pendingEvent.markPublished(now);
            } catch (RuntimeException ex) {
                long retryDelay = computeRetryDelaySeconds(pendingEvent.getAttemptCount() + 1);
                pendingEvent.markRetry(
                        now,
                        now.plusSeconds(retryDelay),
                        effectiveMaxAttempts,
                        ex.getMessage()
                );
            }

            authOutboxEventRepository.save(pendingEvent);
        }
    }

    private long computeRetryDelaySeconds(int nextAttemptNumber) {
        long shift = Math.max(0, Math.min(16, nextAttemptNumber - 1));
        long multiplier = 1L << shift;
        long rawDelay;
        try {
            rawDelay = Math.multiplyExact(Math.max(1L, retryBaseSeconds), multiplier);
        } catch (ArithmeticException ex) {
            rawDelay = retryMaxSeconds;
        }
        return Math.min(Math.max(1L, rawDelay), Math.max(1L, retryMaxSeconds));
    }
}
