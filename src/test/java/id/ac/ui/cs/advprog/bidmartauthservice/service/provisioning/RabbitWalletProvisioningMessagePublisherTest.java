package id.ac.ui.cs.advprog.bidmartauthservice.service.provisioning;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessagePostProcessor;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@Tag("unit")
class RabbitWalletProvisioningMessagePublisherTest {

    @Mock
    private RabbitTemplate rabbitTemplate;

    @Mock
    private WalletProvisioningEventMapper walletProvisioningEventMapper;

    @Test
    void publishShouldSendPersistentJsonMessageWithEventHeaders() {
        RabbitWalletProvisioningMessagePublisher publisher = new RabbitWalletProvisioningMessagePublisher(
                rabbitTemplate,
                walletProvisioningEventMapper
        );
        ReflectionTestUtils.setField(publisher, "exchange", "bidmart.wallet.provisioning");
        ReflectionTestUtils.setField(publisher, "routingKey", "wallet.provision.requested.v1");

        WalletProvisionRequestedEvent event = new WalletProvisionRequestedEvent(
                UUID.randomUUID(),
                UUID.randomUUID(),
                "wallet@test.com",
                Instant.parse("2026-04-16T13:00:00Z"),
                "bidmart-auth-service"
        );
        when(walletProvisioningEventMapper.writePayload(event)).thenReturn("{\"eventId\":\"x\"}");

        publisher.publish(event);

        ArgumentCaptor<MessagePostProcessor> postProcessorCaptor = ArgumentCaptor.forClass(MessagePostProcessor.class);
        verify(rabbitTemplate).convertAndSend(
                eq("bidmart.wallet.provisioning"),
                eq("wallet.provision.requested.v1"),
                eq("{\"eventId\":\"x\"}"),
                postProcessorCaptor.capture()
        );

        Message message = new Message("{}".getBytes(), new MessageProperties());
        Message processed = postProcessorCaptor.getValue().postProcessMessage(message);

        assertEquals(MessageProperties.CONTENT_TYPE_JSON, processed.getMessageProperties().getContentType());
        assertEquals("WalletProvisionRequested.v1", processed.getMessageProperties().getHeaders().get("eventType"));
        assertEquals(event.eventId().toString(), processed.getMessageProperties().getHeaders().get("eventId"));
        assertEquals("bidmart-auth-service", processed.getMessageProperties().getHeaders().get("source"));
    }
}
