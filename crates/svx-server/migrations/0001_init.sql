-- SVX managed service schema, version 1.
-- Times are Unix seconds (UTC). Binary identifiers are BYTEA.

CREATE TABLE orgs (
    org_id         TEXT PRIMARY KEY,
    display_name   TEXT   NOT NULL,
    domain         TEXT   NOT NULL,
    idp_issuer     TEXT   NOT NULL,
    idp_client_id  TEXT   NOT NULL,
    group_claim    TEXT   NOT NULL,
    key_agent_url  TEXT,
    challenge      TEXT   NOT NULL,
    created_at     BIGINT NOT NULL,
    verified_at    BIGINT
);
-- A domain can back at most one verified organization.
CREATE UNIQUE INDEX orgs_verified_domain ON orgs (domain) WHERE verified_at IS NOT NULL;

CREATE TABLE org_admins (
    org_id    TEXT   NOT NULL REFERENCES orgs (org_id) ON DELETE CASCADE,
    subject   TEXT   NOT NULL,
    added_at  BIGINT NOT NULL,
    PRIMARY KEY (org_id, subject)
);

CREATE TABLE org_keys (
    org_id      TEXT   NOT NULL REFERENCES orgs (org_id) ON DELETE CASCADE,
    key_id      BYTEA  NOT NULL CHECK (length(key_id) = 16),
    kind        TEXT   NOT NULL CHECK (kind IN ('ed25519', 'x25519')),
    public_key  BYTEA  NOT NULL CHECK (length(public_key) = 32),
    status      TEXT   NOT NULL CHECK (status IN ('active', 'retired', 'revoked')),
    created_at  BIGINT NOT NULL,
    retired_at  BIGINT,
    revoked_at  BIGINT,
    PRIMARY KEY (org_id, key_id)
);

CREATE TABLE policies (
    org_id      TEXT   NOT NULL REFERENCES orgs (org_id) ON DELETE CASCADE,
    name        TEXT   NOT NULL,
    document    JSONB  NOT NULL,
    updated_at  BIGINT NOT NULL,
    PRIMARY KEY (org_id, name)
);

CREATE TABLE artifacts (
    artifact_id    BYTEA  PRIMARY KEY CHECK (length(artifact_id) = 16),
    sender_org     TEXT   NOT NULL,
    recipient_org  TEXT   NOT NULL,
    header_hash    BYTEA  NOT NULL,
    registered_at  BIGINT NOT NULL
);

-- A revocation only takes effect for artifacts whose signed header names
-- the revoking org as sender or recipient (checked at release time).
CREATE TABLE revocations (
    artifact_id     BYTEA  NOT NULL CHECK (length(artifact_id) = 16),
    revoked_by_org  TEXT   NOT NULL REFERENCES orgs (org_id),
    at              BIGINT NOT NULL,
    PRIMARY KEY (artifact_id, revoked_by_org)
);

-- Single-use release transaction identifiers (replay protection).
CREATE TABLE release_txns (
    txn          BYTEA  PRIMARY KEY CHECK (length(txn) = 16),
    artifact_id  BYTEA  NOT NULL,
    org_id       TEXT   NOT NULL,
    at           BIGINT NOT NULL
);

-- Append-only, per-organization hash-chained audit log.
CREATE TABLE audit (
    org_id       TEXT   NOT NULL,
    seq          BIGINT NOT NULL,
    at           BIGINT NOT NULL,
    event        TEXT   NOT NULL,
    subject      TEXT,
    artifact_id  TEXT,
    txn          TEXT,
    reason       TEXT,
    prev_hash    BYTEA  NOT NULL,
    hash         BYTEA  NOT NULL,
    PRIMARY KEY (org_id, seq)
);
CREATE INDEX audit_subject_recent ON audit (org_id, subject, at);

CREATE FUNCTION svx_audit_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit log is append-only';
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_append_only
    BEFORE UPDATE OR DELETE ON audit
    FOR EACH ROW EXECUTE FUNCTION svx_audit_append_only();
