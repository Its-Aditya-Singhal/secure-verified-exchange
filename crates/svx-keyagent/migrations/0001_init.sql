-- SVX key agent schema, version 1.

-- Single-use release transaction identifiers.
CREATE TABLE agent_txns (
    txn          BYTEA  PRIMARY KEY CHECK (length(txn) = 16),
    artifact_id  BYTEA  NOT NULL,
    subject      TEXT   NOT NULL,
    at           BIGINT NOT NULL
);

-- Append-only local audit log.
CREATE TABLE agent_audit (
    seq          BIGSERIAL PRIMARY KEY,
    at           BIGINT NOT NULL,
    event        TEXT   NOT NULL,
    subject      TEXT,
    artifact_id  TEXT,
    txn          TEXT,
    reason       TEXT
);

CREATE FUNCTION svx_agent_audit_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit log is append-only';
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER agent_audit_append_only
    BEFORE UPDATE OR DELETE ON agent_audit
    FOR EACH ROW EXECUTE FUNCTION svx_agent_audit_append_only();
