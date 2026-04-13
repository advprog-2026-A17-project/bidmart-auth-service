package id.ac.ui.cs.advprog.bidmartauthservice.service;

import java.time.Instant;
import java.util.UUID;

public record AuthDomainEvent(
        String eventType,
        UUID userId,
        String email,
        Instant occurredAt
) {
}
