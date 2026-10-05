-- Suspending accounts and erasing them on request (`svx-admin`).

ALTER TABLE orgs ADD COLUMN suspended_at BIGINT;
ALTER TABLE orgs ADD COLUMN suspended_reason TEXT;

-- The audit log stays append-only: no UPDATE ever. A DELETE is allowed
-- only inside a transaction that set `svx.erasure` (svx-admin delete),
-- which removes an erased account's whole log, never part of a chain.
CREATE OR REPLACE FUNCTION svx_audit_append_only() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' AND current_setting('svx.erasure', true) = 'on' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'audit log is append-only';
END
$$ LANGUAGE plpgsql;
