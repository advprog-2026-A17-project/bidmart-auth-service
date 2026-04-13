package id.ac.ui.cs.advprog.bidmartauthservice.service;

import id.ac.ui.cs.advprog.bidmartauthservice.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
@RequiredArgsConstructor
public class SpringAuthEventPublisher implements AuthEventPublisher {

    private final ApplicationEventPublisher eventPublisher;

    @Override
    public void publishUserRegistered(User user) {
        eventPublisher.publishEvent(new AuthDomainEvent(
                "UserRegistered",
                user.getId(),
                user.getEmail(),
                Instant.now()
        ));
    }

    @Override
    public void publishEmailVerified(User user) {
        eventPublisher.publishEvent(new AuthDomainEvent(
                "EmailVerified",
                user.getId(),
                user.getEmail(),
                Instant.now()
        ));
    }

    @Override
    public void publishUserDisabled(User user) {
        eventPublisher.publishEvent(new AuthDomainEvent(
                "UserDisabled",
                user.getId(),
                user.getEmail(),
                Instant.now()
        ));
    }
}
