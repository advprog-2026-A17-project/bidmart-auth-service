package id.ac.ui.cs.advprog.bidmartauthservice.service;

import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@Tag("unit")
class SpringAuthEventPublisherTest {

    private final ApplicationEventPublisher applicationEventPublisher = mock(ApplicationEventPublisher.class);
    private final SpringAuthEventPublisher publisher = new SpringAuthEventPublisher(applicationEventPublisher);

    @Test
    void publishesUserRegisteredEvent() {
        User user = user();

        publisher.publishUserRegistered(user);

        AuthDomainEvent event = capturedEvent();
        assertEquals("UserRegistered", event.eventType());
        assertEquals(user.getId(), event.userId());
        assertEquals(user.getEmail(), event.email());
        assertNotNull(event.occurredAt());
    }

    @Test
    void publishesEmailVerifiedEvent() {
        User user = user();

        publisher.publishEmailVerified(user);

        AuthDomainEvent event = capturedEvent();
        assertEquals("EmailVerified", event.eventType());
        assertEquals(user.getId(), event.userId());
        assertEquals(user.getEmail(), event.email());
    }

    @Test
    void publishesUserDisabledEvent() {
        User user = user();

        publisher.publishUserDisabled(user);

        AuthDomainEvent event = capturedEvent();
        assertEquals("UserDisabled", event.eventType());
        assertEquals(user.getId(), event.userId());
        assertEquals(user.getEmail(), event.email());
    }

    private AuthDomainEvent capturedEvent() {
        ArgumentCaptor<AuthDomainEvent> captor = ArgumentCaptor.forClass(AuthDomainEvent.class);
        verify(applicationEventPublisher).publishEvent(captor.capture());
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
