package id.ac.ui.cs.advprog.bidmartauthservice.service.provisioning;

import java.time.Instant;
import java.util.UUID;

public record WalletProvisionRequestedEvent(
        UUID eventId,
        UUID userId,
        String email,
        Instant occurredAt,
        String source
) {
    public static final String EVENT_TYPE = "WalletProvisionRequested.v1";
}
