package id.ac.ui.cs.advprog.bidmartauthservice.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.messaging.simp.SimpMessagingTemplate;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SessionRevokePublisherTest {

    @Mock
    private SimpMessagingTemplate messagingTemplate;

    @InjectMocks
    private SessionRevokePublisher sessionRevokePublisher;

    @Captor
    private ArgumentCaptor<SessionRevokePublisher.SessionRevokeEvent> eventCaptor;

    @Test
    void testPublishSessionRevoked_Success() {
        UUID testTokenId = UUID.randomUUID();
        String reason = "USER_LOGOUT";

        sessionRevokePublisher.publishSessionRevoked(testTokenId, reason);

        verify(messagingTemplate, times(1)).convertAndSend(
                eq("/topic/sessions/" + testTokenId),
                eventCaptor.capture()
        );

        SessionRevokePublisher.SessionRevokeEvent capturedEvent = eventCaptor.getValue();
        assertEquals(testTokenId.toString(), capturedEvent.tokenId());
        assertEquals(reason, capturedEvent.reason());
        assertTrue(capturedEvent.timestamp() <= System.currentTimeMillis());
    }

    @Test
    void testPublishSessionRevoked_ExceptionCaught() {
        UUID testTokenId = UUID.randomUUID();
        
        doThrow(new RuntimeException("Message broker down"))
                .when(messagingTemplate)
                .convertAndSend(anyString(), any(Object.class));

        assertDoesNotThrow(() -> sessionRevokePublisher.publishSessionRevoked(testTokenId, "ADMIN_REVOKE"));
    }
}