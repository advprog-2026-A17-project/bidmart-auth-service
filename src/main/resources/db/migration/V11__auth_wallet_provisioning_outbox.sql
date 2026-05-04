CREATE TABLE auth_outbox_events (
    id UUID PRIMARY KEY,
    aggregate_type VARCHAR(64) NOT NULL,
    aggregate_id UUID NOT NULL,
    event_type VARCHAR(128) NOT NULL,
    payload TEXT NOT NULL,
    status VARCHAR(32) NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    published_at TIMESTAMP,
    last_error TEXT
);

CREATE INDEX idx_auth_outbox_status_next_attempt
    ON auth_outbox_events(status, next_attempt_at);

CREATE INDEX idx_auth_outbox_aggregate
    ON auth_outbox_events(aggregate_type, aggregate_id);
