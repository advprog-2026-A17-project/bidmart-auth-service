CREATE TABLE email_verification_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_sent_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_email_verification_tokens_user
        FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE CASCADE
);

CREATE INDEX idx_email_verification_tokens_user_id
    ON email_verification_tokens(user_id);

CREATE INDEX idx_email_verification_tokens_expires_at
    ON email_verification_tokens(expires_at);
