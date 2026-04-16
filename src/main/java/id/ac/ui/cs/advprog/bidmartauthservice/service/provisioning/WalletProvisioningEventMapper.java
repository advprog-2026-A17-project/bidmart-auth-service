package id.ac.ui.cs.advprog.bidmartauthservice.service.provisioning;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class WalletProvisioningEventMapper {

    private final ObjectMapper objectMapper;

    @Value("${app.auth.wallet-provisioning.source:bidmart-auth-service}")
    private String source;

    public WalletProvisionRequestedEvent toEvent(User user, Instant occurredAt) {
        if (user == null || user.getId() == null || user.getEmail() == null || user.getEmail().isBlank()) {
            throw new IllegalArgumentException("User identity is required for wallet provisioning event");
        }

        return new WalletProvisionRequestedEvent(
                UUID.randomUUID(),
                user.getId(),
                user.getEmail(),
                occurredAt,
                source
        );
    }

    public String writePayload(WalletProvisionRequestedEvent event) {
        try {
            return objectMapper.writeValueAsString(event);
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("Failed to serialize wallet provisioning payload", ex);
        }
    }

    public WalletProvisionRequestedEvent readPayload(String payload) {
        try {
            return objectMapper.readValue(payload, WalletProvisionRequestedEvent.class);
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("Failed to deserialize wallet provisioning payload", ex);
        }
    }
}
