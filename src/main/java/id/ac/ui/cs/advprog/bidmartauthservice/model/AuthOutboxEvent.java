package id.ac.ui.cs.advprog.bidmartauthservice.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "auth_outbox_events")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthOutboxEvent {

    private static final int LAST_ERROR_MAX_LENGTH = 2000;

    @Id
    private UUID id;

    @Column(name = "aggregate_type", nullable = false, length = 64)
    private String aggregateType;

    @Column(name = "aggregate_id", nullable = false)
    private UUID aggregateId;

    @Column(name = "event_type", nullable = false, length = 128)
    private String eventType;

    @Column(name = "payload", nullable = false, columnDefinition = "TEXT")
    private String payload;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 32)
    @Builder.Default
    private AuthOutboxEventStatus status = AuthOutboxEventStatus.PENDING;

    @Column(name = "attempt_count", nullable = false)
    @Builder.Default
    private int attemptCount = 0;

    @Column(name = "next_attempt_at", nullable = false)
    private Instant nextAttemptAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "published_at")
    private Instant publishedAt;

    @Column(name = "last_error", columnDefinition = "TEXT")
    private String lastError;

    public void markPublished(Instant publishedAt) {
        this.status = AuthOutboxEventStatus.PUBLISHED;
        this.publishedAt = publishedAt;
        this.lastError = null;
        this.attemptCount += 1;
        this.nextAttemptAt = publishedAt;
    }

    public void markRetry(Instant now, Instant nextAttemptAt, int maxAttempts, String errorMessage) {
        this.attemptCount += 1;
        this.lastError = truncate(errorMessage);
        if (this.attemptCount >= maxAttempts) {
            this.status = AuthOutboxEventStatus.FAILED;
            this.nextAttemptAt = now;
            return;
        }

        this.status = AuthOutboxEventStatus.RETRY;
        this.nextAttemptAt = nextAttemptAt;
    }

    private String truncate(String value) {
        if (value == null || value.length() <= LAST_ERROR_MAX_LENGTH) {
            return value;
        }
        return value.substring(0, LAST_ERROR_MAX_LENGTH);
    }
}
