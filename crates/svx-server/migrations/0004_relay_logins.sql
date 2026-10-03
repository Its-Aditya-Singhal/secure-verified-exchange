-- Relayed sign-ins (Phase 5d): providers like Apple don't accept a desktop
-- app's loopback redirect and need a secret only the service may hold, so
-- the service receives the provider's callback, exchanges the code, checks
-- the ID token and hands it to the app that knows `secret` (only its hash
-- is stored). Rows live 10 minutes and are deleted once collected.

CREATE TABLE relay_logins (
    relay_id       BYTEA  PRIMARY KEY CHECK (length(relay_id) = 16),
    state          TEXT   NOT NULL UNIQUE,
    issuer         TEXT   NOT NULL,
    nonce          TEXT   NOT NULL,
    secret_hash    BYTEA  NOT NULL CHECK (length(secret_hash) = 32),
    pkce_verifier  TEXT   NOT NULL,
    created_at     BIGINT NOT NULL,
    id_token       TEXT,
    error          TEXT
);
CREATE INDEX relay_logins_created ON relay_logins (created_at);
