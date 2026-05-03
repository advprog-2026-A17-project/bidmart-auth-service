package id.ac.ui.cs.advprog.bidmartauthservice.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

/**
 * Service for publishing real-time session revocation events via WebSocket.
 * Used to notify clients when their sessions are revoked.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SessionRevokePublisher {

    private final SimpMessagingTemplate messagingTemplate;

    /**
     * Publish a session revocation event to the client's WebSocket subscription.
     * The client listens on "/topic/sessions/{tokenId}" and receives this message.
     *
     * @param tokenId The ID of the revoked session token
     * @param reason  The reason for revocation (e.g., "USER_LOGOUT", "ADMIN_REVOKE", "CONCURRENT_SESSION_LIMIT")
     */
    public void publishSessionRevoked(UUID tokenId, String reason) {
        try {
            String destination = "/topic/sessions/" + tokenId;
            SessionRevokeEvent event = new SessionRevokeEvent(
                    tokenId.toString(),
                    reason,
                    Instant.now().toEpochMilli()
            );
            messagingTemplate.convertAndSend(destination, event);
            log.info("Published session revocation event for tokenId: {} (reason: {})", tokenId, reason);
        } catch (Exception e) {
            log.error("Failed to publish session revocation event for tokenId: {}", tokenId, e);
        }
    }

    /**
     * DTO for session revocation events sent to clients.
     */
    public record SessionRevokeEvent(
            String tokenId,
            String reason,
            long timestamp
    ) {
    }
}
