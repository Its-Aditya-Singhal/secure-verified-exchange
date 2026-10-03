-- Personal accounts (Phase 5d): a one-person organization signed up with
-- Google or Apple, files with per-file rules, sender approval and one-time
-- opening. File names and contents never reach the service.

ALTER TABLE orgs ADD COLUMN kind TEXT NOT NULL DEFAULT 'company'
    CHECK (kind IN ('company', 'personal'));
-- Domain proof is for companies only; personal accounts share email domains.
DROP INDEX orgs_verified_domain;
CREATE UNIQUE INDEX orgs_verified_domain ON orgs (domain)
    WHERE verified_at IS NOT NULL AND kind = 'company';

-- The person behind a personal account: bound to the provider's (issuer,
-- subject), which never changes; the verified email is for the directory.
CREATE TABLE personal_accounts (
    org_id      TEXT   PRIMARY KEY REFERENCES orgs (org_id) ON DELETE CASCADE,
    issuer      TEXT   NOT NULL,
    subject     TEXT   NOT NULL,
    email       TEXT   NOT NULL,
    created_at  BIGINT NOT NULL,
    UNIQUE (issuer, subject)
);
CREATE UNIQUE INDEX personal_accounts_email ON personal_accounts (lower(email));

-- Nonces of signed device requests (replay protection), kept a few minutes.
CREATE TABLE request_nonces (
    nonce  BYTEA  PRIMARY KEY CHECK (length(nonce) = 16),
    at     BIGINT NOT NULL
);
CREATE INDEX request_nonces_at ON request_nonces (at);

-- A file a personal account made, with the rules its sender controls.
CREATE TABLE personal_files (
    artifact_id        BYTEA   PRIMARY KEY CHECK (length(artifact_id) = 16),
    sender             TEXT    NOT NULL REFERENCES orgs (org_id),
    header_hash        BYTEA   NOT NULL CHECK (length(header_hash) = 32),
    created_at         BIGINT  NOT NULL,
    signed_expires_at  BIGINT,
    require_approval   BOOLEAN NOT NULL,
    one_time           BOOLEAN NOT NULL,
    expires_at         BIGINT,
    revoked_at         BIGINT,
    registered_at      BIGINT  NOT NULL
);
CREATE INDEX personal_files_sender ON personal_files (sender, created_at);

CREATE TABLE personal_file_recipients (
    artifact_id  BYTEA  NOT NULL REFERENCES personal_files (artifact_id) ON DELETE CASCADE,
    recipient    TEXT   NOT NULL,
    position     INT    NOT NULL,
    revoked_at   BIGINT,
    PRIMARY KEY (artifact_id, recipient)
);
CREATE INDEX personal_file_recipients_recipient ON personal_file_recipients (recipient);

-- Requests to open a file that wait for (or got) the sender's decision.
-- An approval lets that recipient open the file for 24 hours.
CREATE TABLE approvals (
    request_id    BYTEA  PRIMARY KEY CHECK (length(request_id) = 16),
    artifact_id   BYTEA  NOT NULL REFERENCES personal_files (artifact_id) ON DELETE CASCADE,
    requester     TEXT   NOT NULL,
    state         TEXT   NOT NULL CHECK (state IN ('pending', 'approved', 'declined')),
    requested_at  BIGINT NOT NULL,
    decided_at    BIGINT,
    expires_at    BIGINT NOT NULL
);
CREATE INDEX approvals_file_requester ON approvals (artifact_id, requester, requested_at);

-- Opens per (file, recipient). A one-time open is final once the recipient
-- confirms decryption, or 10 minutes after the first release.
CREATE TABLE opens (
    artifact_id        BYTEA  NOT NULL,
    recipient          TEXT   NOT NULL,
    first_released_at  BIGINT NOT NULL,
    last_released_at   BIGINT NOT NULL,
    final_at           BIGINT,
    PRIMARY KEY (artifact_id, recipient)
);

-- Emails to send (approval requests). No file names or contents.
CREATE TABLE notifications (
    id          BIGSERIAL PRIMARY KEY,
    to_email    TEXT   NOT NULL,
    subject     TEXT   NOT NULL,
    body        TEXT   NOT NULL,
    dedupe_key  TEXT   NOT NULL UNIQUE,
    created_at  BIGINT NOT NULL,
    sent_at     BIGINT
);
