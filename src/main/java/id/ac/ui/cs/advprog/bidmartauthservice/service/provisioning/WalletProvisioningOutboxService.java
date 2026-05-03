package id.ac.ui.cs.advprog.bidmartauthservice.service.provisioning;

import id.ac.ui.cs.advprog.bidmartauthservice.model.AuthOutboxEvent;
import id.ac.ui.cs.advprog.bidmartauthservice.model.AuthOutboxEventStatus;
import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import id.ac.ui.cs.advprog.bidmartauthservice.repository.AuthOutboxEventRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class WalletProvisioningOutboxService {

    private static final String AGGREGATE_TYPE = "USER";

    private final AuthOutboxEventRepository authOutboxEventRepository;
    private final WalletProvisioningEventMapper walletProvisioningEventMapper;

    @Transactional(propagation = Propagation.MANDATORY)
    public void enqueueWalletProvisionRequested(User user) {
        Instant now = Instant.now();
        WalletProvisionRequestedEvent event = walletProvisioningEventMapper.toEvent(user, now);

        AuthOutboxEvent outboxEvent = AuthOutboxEvent.builder()
                .id(event.eventId())
                .aggregateType(AGGREGATE_TYPE)
                .aggregateId(event.userId())
                .eventType(WalletProvisionRequestedEvent.EVENT_TYPE)
                .payload(walletProvisioningEventMapper.writePayload(event))
                .status(AuthOutboxEventStatus.PENDING)
                .attemptCount(0)
                .nextAttemptAt(now)
                .createdAt(now)
                .build();

        authOutboxEventRepository.save(outboxEvent);
    }
}
