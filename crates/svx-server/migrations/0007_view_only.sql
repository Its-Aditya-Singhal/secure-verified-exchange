-- View-only files (Phase 7): the sender can limit a file to viewing inside
-- the app, and let recipients ask to turn it into a normal file. Share
-- requests are approvals of another kind, so Requests works unchanged.
ALTER TABLE personal_files ADD COLUMN view_only BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE personal_files ADD COLUMN allow_share_requests BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE approvals ADD COLUMN kind TEXT NOT NULL DEFAULT 'open' CHECK (kind IN ('open', 'share'));
