-- One row per email the service or the operator's tools send, so every
-- process shares one count of the mail account's daily allowance (Gmail
-- counts the last 24 hours). Pruned after 7 days.
CREATE TABLE email_sends (
    id BIGSERIAL PRIMARY KEY,
    at BIGINT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('code', 'notice', 'admin', 'announcement', 'test'))
);
CREATE INDEX email_sends_at ON email_sends (at);

-- What the operator did (svx-admin and the admin page). Account IDs only,
-- never email addresses, so an erased account leaves no address behind.
CREATE TABLE admin_log (
    id BIGSERIAL PRIMARY KEY,
    at BIGINT NOT NULL,
    action TEXT NOT NULL,
    org_id TEXT,
    detail TEXT
);
CREATE INDEX admin_log_at ON admin_log (at);

-- The operator's logs page reads every account's audit log, newest first.
CREATE INDEX audit_at ON audit (at);

-- Announcements: emails from the operator to chosen accounts, sent one per
-- person by the service's worker within the daily allowance.
ALTER TABLE personal_accounts ADD COLUMN announcements_off BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE announcements (
    id BIGSERIAL PRIMARY KEY,
    created_at BIGINT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    -- 'sending' until every recipient is done or it's stopped.
    status TEXT NOT NULL CHECK (status IN ('sending', 'done', 'stopped')),
    queue_rest BOOLEAN NOT NULL
);

-- Deleted once the announcement is done or stopped.
CREATE TABLE announcement_files (
    id BIGSERIAL PRIMARY KEY,
    announcement_id BIGINT NOT NULL REFERENCES announcements (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    content_type TEXT NOT NULL,
    data BYTEA NOT NULL
);

CREATE TABLE announcement_recipients (
    announcement_id BIGINT NOT NULL REFERENCES announcements (id) ON DELETE CASCADE,
    org_id TEXT NOT NULL,
    email TEXT NOT NULL,
    -- 'pending', 'sent', 'failed', 'skipped' (suspended or opted out by
    -- the time it was their turn), 'stopped'.
    state TEXT NOT NULL CHECK (state IN ('pending', 'sent', 'failed', 'skipped', 'stopped')),
    done_at BIGINT,
    error TEXT,
    PRIMARY KEY (announcement_id, org_id)
);
CREATE INDEX announcement_recipients_pending ON announcement_recipients (announcement_id)
    WHERE state = 'pending';
