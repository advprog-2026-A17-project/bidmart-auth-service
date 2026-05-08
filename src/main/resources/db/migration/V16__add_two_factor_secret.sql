ALTER TABLE two_factor_challenges ADD COLUMN secret VARCHAR(255);

ALTER TABLE two_factor_challenges ALTER COLUMN token_hash DROP NOT NULL;