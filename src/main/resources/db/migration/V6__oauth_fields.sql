ALTER TABLE users
    ADD COLUMN oauth_provider VARCHAR(64),
    ADD COLUMN oauth_subject VARCHAR(255);

CREATE INDEX idx_users_oauth_identity ON users(oauth_provider, oauth_subject);
