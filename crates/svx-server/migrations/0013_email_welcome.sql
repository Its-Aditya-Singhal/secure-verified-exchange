-- The one-time welcome email to a new account counts towards the daily
-- allowance too.
ALTER TABLE email_sends DROP CONSTRAINT email_sends_kind_check;
ALTER TABLE email_sends ADD CONSTRAINT email_sends_kind_check
    CHECK (kind IN ('code', 'notice', 'admin', 'announcement', 'test', 'alert', 'welcome'));
