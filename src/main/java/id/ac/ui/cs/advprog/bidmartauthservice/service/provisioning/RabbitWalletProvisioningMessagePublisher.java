package id.ac.ui.cs.advprog.bidmartauthservice.service.provisioning;

import lombok.RequiredArgsConstructor;
import org.springframework.amqp.core.MessageDeliveryMode;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class RabbitWalletProvisioningMessagePublisher implements WalletProvisioningMessagePublisher {

    private final RabbitTemplate rabbitTemplate;
    private final WalletProvisioningEventMapper walletProvisioningEventMapper;

    @Value("${app.auth.wallet-provisioning.exchange:bidmart.wallet.provisioning}")
    private String exchange;

    @Value("${app.auth.wallet-provisioning.routing-key:wallet.provision.requested.v1}")
    private String routingKey;

    @Override
    public void publish(WalletProvisionRequestedEvent event) {
        String payload = walletProvisioningEventMapper.writePayload(event);

        rabbitTemplate.convertAndSend(exchange, routingKey, payload, message -> {
            message.getMessageProperties().setContentType(MessageProperties.CONTENT_TYPE_JSON);
            message.getMessageProperties().setDeliveryMode(MessageDeliveryMode.PERSISTENT);
            message.getMessageProperties().setHeader("eventType", WalletProvisionRequestedEvent.EVENT_TYPE);
            message.getMessageProperties().setHeader("eventId", event.eventId().toString());
            message.getMessageProperties().setHeader("source", event.source());
            message.getMessageProperties().setHeader("occurredAt", event.occurredAt().toString());
            return message;
        });
    }
}
