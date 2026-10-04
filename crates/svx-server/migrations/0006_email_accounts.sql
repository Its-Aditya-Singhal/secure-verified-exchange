-- Phase 6: Apple sign-in is gone (it needs a paid Apple developer account);
-- people without Google create an account with an email address and a
-- password instead. The service is their sign-in provider (issuer
-- 'svx:email', subject = the lower-cased email).

DROP TABLE IF EXISTS relay_logins;

ALTER TABLE personal_accounts ADD COLUMN first_name TEXT;
ALTER TABLE personal_accounts ADD COLUMN last_name TEXT;

-- The password of an email account (Argon2id, `svx_crypto::hash_password`).
CREATE TABLE email_accounts (
    org_id               TEXT    PRIMARY KEY REFERENCES orgs (org_id) ON DELETE CASCADE,
    password_hash        TEXT    NOT NULL,
    -- Wrong passwords in a row; too many lock the account for a while.
    failed               INTEGER NOT NULL DEFAULT 0,
    locked_until         BIGINT  NOT NULL DEFAULT 0,
    password_changed_at  BIGINT  NOT NULL
);

-- Emailed six-digit codes. Only a hash of the code is kept; a code is
-- used once, expires after a few minutes and allows a few tries.
CREATE TABLE email_challenges (
    challenge   BYTEA   PRIMARY KEY CHECK (length(challenge) = 16),
    email_lc    TEXT    NOT NULL,
    purpose     TEXT    NOT NULL CHECK (purpose IN ('sign_up', 'sign_in', 'reset_password')),
    code_hash   BYTEA   NOT NULL CHECK (length(code_hash) = 32),
    created_at  BIGINT  NOT NULL,
    expires_at  BIGINT  NOT NULL,
    tries       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX email_challenges_email ON email_challenges (email_lc, created_at);
