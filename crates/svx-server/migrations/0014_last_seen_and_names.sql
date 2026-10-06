-- When an account last used the app (any accepted signed request, written at
-- most every 5 minutes), for the operator's "last active".
ALTER TABLE personal_accounts ADD COLUMN last_seen_at BIGINT;

-- Google accounts have no name at sign-up; the app asks for it afterwards
-- (PUT /v1/me/name), and the welcome email waits for it.
ALTER TABLE personal_accounts ADD COLUMN welcome_pending BOOLEAN NOT NULL DEFAULT false;
