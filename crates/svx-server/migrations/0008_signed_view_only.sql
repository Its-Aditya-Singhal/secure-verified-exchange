-- View-only signed into the file (format 1.4). A file registered with the
-- flag can be relaxed later, but a normal file can't become view-only: its
-- payload isn't a view-only container, so nobody could open it any more.
ALTER TABLE personal_files ADD COLUMN signed_view_only BOOLEAN NOT NULL DEFAULT FALSE;
UPDATE personal_files SET signed_view_only = view_only;
