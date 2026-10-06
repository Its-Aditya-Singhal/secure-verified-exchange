-- An approved copy request (kind 'share') allows one save of a view-only
-- file, even after a one-time view. used_at: the first save released while
-- the approval was in effect (by any path); final_at: the recipient's
-- receipt for it. Once final, or 10 minutes after used_at, it is spent.
ALTER TABLE approvals ADD COLUMN used_at BIGINT;
ALTER TABLE approvals ADD COLUMN final_at BIGINT;
