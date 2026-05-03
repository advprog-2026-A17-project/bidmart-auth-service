package id.ac.ui.cs.advprog.bidmartauthservice.service.provisioning;

import com.fasterxml.jackson.databind.ObjectMapper;
import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Tag("unit")
class WalletProvisioningEventMapperTest {

    @Test
    void toEventShouldMapRequiredContractFields() {
        WalletProvisioningEventMapper mapper = new WalletProvisioningEventMapper(new ObjectMapper().findAndRegisterModules());
        ReflectionTestUtils.setField(mapper, "source", "bidmart-auth-service");

        User user = User.builder()
                .id(UUID.randomUUID())
                .email("wallet@test.com")
                .build();

        Instant occurredAt = Instant.parse("2026-04-16T13:00:00Z");
        WalletProvisionRequestedEvent event = mapper.toEvent(user, occurredAt);

        assertNotNull(event.eventId());
        assertEquals(user.getId(), event.userId());
        assertEquals("wallet@test.com", event.email());
        assertEquals(occurredAt, event.occurredAt());
        assertEquals("bidmart-auth-service", event.source());
    }

    @Test
    void writeAndReadPayloadShouldPreserveEventData() {
        WalletProvisioningEventMapper mapper = new WalletProvisioningEventMapper(new ObjectMapper().findAndRegisterModules());
        ReflectionTestUtils.setField(mapper, "source", "bidmart-auth-service");

        WalletProvisionRequestedEvent event = new WalletProvisionRequestedEvent(
                UUID.randomUUID(),
                UUID.randomUUID(),
                "wallet@test.com",
                Instant.parse("2026-04-16T13:00:00Z"),
                "bidmart-auth-service"
        );

        String payload = mapper.writePayload(event);
        WalletProvisionRequestedEvent reloaded = mapper.readPayload(payload);

        assertEquals(event, reloaded);
    }

    @Test
    void toEventShouldRejectMissingUserIdentity() {
        WalletProvisioningEventMapper mapper = new WalletProvisioningEventMapper(new ObjectMapper().findAndRegisterModules());
        ReflectionTestUtils.setField(mapper, "source", "bidmart-auth-service");

        User invalidUser = User.builder()
                .id(null)
                .email("")
                .build();

        assertThrows(IllegalArgumentException.class, () -> mapper.toEvent(invalidUser, Instant.now()));
    }
}
