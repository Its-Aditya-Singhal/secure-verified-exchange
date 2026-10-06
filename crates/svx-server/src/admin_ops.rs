//! Operator commands behind `svx-admin`: counts, finding accounts,
//! suspending them and erasing them on request. They work on the database
//! directly and are run on the server (over SSH). The admin page
//! ([`crate::admin_web`]) uses them too, on loopback only.

use std::fmt;

use sqlx::{FromRow, PgPool};
use svx_protocol::unix_now;

use crate::audit;
use crate::notify::Email;

/// Service-wide counts.
#[derive(Debug, Default, serde::Serialize)]
pub struct Stats {
    pub accounts: i64,
    pub accounts_7d: i64,
    pub accounts_30d: i64,
    pub google_accounts: i64,
    pub email_accounts: i64,
    pub suspended: i64,
    pub files: i64,
    pub files_7d: i64,
    pub opens_7d: i64,
    pub pending_approvals: i64,
    pub database_bytes: i64,
}

impl fmt::Display for Stats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "accounts           {} ({} new in 7 days, {} in 30 days)",
            self.accounts, self.accounts_7d, self.accounts_30d
        )?;
        writeln!(
            f,
            "  by sign-in       {} Google, {} email",
            self.google_accounts, self.email_accounts
        )?;
        writeln!(f, "  suspended        {}", self.suspended)?;
        writeln!(
            f,
            "files registered   {} ({} in 7 days)",
            self.files, self.files_7d
        )?;
        writeln!(f, "opens in 7 days    {}", self.opens_7d)?;
        writeln!(f, "pending approvals  {}", self.pending_approvals)?;
        write!(
            f,
            "database size      {:.1} MB",
            self.database_bytes as f64 / 1_000_000.0
        )
    }
}

pub async fn stats(db: &PgPool) -> sqlx::Result<Stats> {
    let now = unix_now();
    let (week, month) = (now - 7 * 86_400, now - 30 * 86_400);
    let count = |sql: &'static str, t: Option<i64>| async move {
        let q = sqlx::query_scalar::<_, i64>(sql);
        match t {
            Some(t) => q.bind(t).fetch_one(db).await,
            None => q.fetch_one(db).await,
        }
    };
    Ok(Stats {
        accounts: count("SELECT count(*) FROM personal_accounts", None).await?,
        accounts_7d: count(
            "SELECT count(*) FROM personal_accounts WHERE created_at >= $1",
            Some(week),
        )
        .await?,
        accounts_30d: count(
            "SELECT count(*) FROM personal_accounts WHERE created_at >= $1",
            Some(month),
        )
        .await?,
        google_accounts: count(
            "SELECT count(*) FROM personal_accounts WHERE issuer <> 'svx:email'",
            None,
        )
        .await?,
        email_accounts: count(
            "SELECT count(*) FROM personal_accounts WHERE issuer = 'svx:email'",
            None,
        )
        .await?,
        suspended: count(
            "SELECT count(*) FROM orgs WHERE kind = 'personal' AND suspended_at IS NOT NULL",
            None,
        )
        .await?,
        files: count("SELECT count(*) FROM personal_files", None).await?,
        files_7d: count(
            "SELECT count(*) FROM personal_files WHERE registered_at >= $1",
            Some(week),
        )
        .await?,
        opens_7d: count(
            "SELECT count(*) FROM opens WHERE last_released_at >= $1",
            Some(week),
        )
        .await?,
        pending_approvals: count(
            "SELECT count(*) FROM approvals WHERE state = 'pending' AND expires_at > $1",
            Some(now),
        )
        .await?,
        database_bytes: count("SELECT pg_database_size(current_database())", None).await?,
    })
}

/// One personal account as the operator sees it.
#[derive(Debug, Clone, FromRow)]
pub struct User {
    pub org_id: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub issuer: String,
    pub created_at: i64,
    pub suspended_at: Option<i64>,
    pub suspended_reason: Option<String>,
    /// Latest file sent or opened.
    pub last_active: Option<i64>,
    /// The person asked not to get announcement emails.
    pub announcements_off: bool,
}

impl User {
    pub fn sign_in(&self) -> &str {
        match self.issuer.as_str() {
            "svx:email" => "email",
            "https://accounts.google.com" => "Google",
            other => other,
        }
    }

    pub fn name(&self) -> String {
        match (&self.first_name, &self.last_name) {
            (Some(f), Some(l)) => format!("{f} {l}"),
            _ => String::new(),
        }
    }
}

const USER_SELECT: &str = "SELECT p.org_id, p.email, p.first_name, p.last_name, p.issuer, \
     p.created_at, o.suspended_at, o.suspended_reason, p.announcements_off, \
     GREATEST((SELECT max(registered_at) FROM personal_files WHERE sender = p.org_id), \
              (SELECT max(last_released_at) FROM opens WHERE recipient = p.org_id), \
              p.last_seen_at, p.created_at) AS last_active \
     FROM personal_accounts p JOIN orgs o ON o.org_id = p.org_id";

/// Accounts, newest first; `search` matches email, name or account ID.
pub async fn users(db: &PgPool, search: Option<&str>, limit: i64) -> sqlx::Result<Vec<User>> {
    let pattern = search.map(|s| {
        let escaped = s
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        format!("%{}%", escaped.to_lowercase())
    });
    sqlx::query_as::<_, User>(&format!(
        "{USER_SELECT} WHERE $1::text IS NULL \
           OR lower(p.email) LIKE $1 OR p.org_id LIKE $1 \
           OR lower(coalesce(p.first_name, '') || ' ' || coalesce(p.last_name, '')) LIKE $1 \
         ORDER BY p.created_at DESC, p.org_id LIMIT $2"
    ))
    .bind(pattern)
    .bind(limit.clamp(1, 10_000))
    .fetch_all(db)
    .await
}

/// The account with this email address (any case) or account ID.
pub async fn find(db: &PgPool, who: &str) -> sqlx::Result<Option<User>> {
    sqlx::query_as::<_, User>(&format!(
        "{USER_SELECT} WHERE lower(p.email) = lower($1) OR p.org_id = $1"
    ))
    .bind(who.trim())
    .fetch_optional(db)
    .await
}

/// What an account has done, for `svx-admin user`.
#[derive(Debug, Default, serde::Serialize)]
pub struct Activity {
    pub files_sent: i64,
    pub files_received: i64,
    pub opens: i64,
    pub pending_approvals: i64,
    pub active_keys: i64,
}

pub async fn activity(db: &PgPool, org_id: &str) -> sqlx::Result<Activity> {
    let one = |sql: &'static str| async move {
        sqlx::query_scalar::<_, i64>(sql)
            .bind(org_id)
            .fetch_one(db)
            .await
    };
    Ok(Activity {
        files_sent: one("SELECT count(*) FROM personal_files WHERE sender = $1").await?,
        files_received: one("SELECT count(*) FROM personal_file_recipients WHERE recipient = $1")
            .await?,
        opens: one("SELECT count(*) FROM opens WHERE recipient = $1").await?,
        pending_approvals: one(
            "SELECT count(*) FROM approvals a JOIN personal_files f USING (artifact_id) \
             WHERE f.sender = $1 AND a.state = 'pending'",
        )
        .await?,
        active_keys: one("SELECT count(*) FROM org_keys WHERE org_id = $1 AND status = 'active'")
            .await?,
    })
}

/// Suspend a personal account: it can't sign in or make requests, nobody
/// can address new files to it, and files it sent stop opening.
pub async fn suspend(db: &PgPool, org_id: &str, reason: Option<&str>) -> sqlx::Result<bool> {
    let changed = sqlx::query(
        "UPDATE orgs SET suspended_at = $2, suspended_reason = $3 \
         WHERE org_id = $1 AND kind = 'personal' AND suspended_at IS NULL",
    )
    .bind(org_id)
    .bind(unix_now())
    .bind(reason)
    .execute(db)
    .await?
    .rows_affected()
        == 1;
    if changed {
        log_action(db, "suspended", Some(org_id), reason).await?;
        audit::append(
            db,
            org_id,
            audit::Record {
                event: audit::event::ACCOUNT_SUSPENDED,
                reason: reason.map(str::to_owned),
                ..Default::default()
            },
        )
        .await?;
    }
    Ok(changed)
}

/// Lift a suspension.
pub async fn unsuspend(db: &PgPool, org_id: &str) -> sqlx::Result<bool> {
    let changed = sqlx::query(
        "UPDATE orgs SET suspended_at = NULL, suspended_reason = NULL \
         WHERE org_id = $1 AND kind = 'personal' AND suspended_at IS NOT NULL",
    )
    .bind(org_id)
    .execute(db)
    .await?
    .rows_affected()
        == 1;
    if changed {
        log_action(db, "unsuspended", Some(org_id), None).await?;
        audit::append(
            db,
            org_id,
            audit::Record {
                event: audit::event::ACCOUNT_UNSUSPENDED,
                ..Default::default()
            },
        )
        .await?;
    }
    Ok(changed)
}

/// Erase a personal account on request, in one transaction: its files
/// (and their recipients and approvals), approvals it asked for, its open
/// records, its place on other people's files, its revocations, emails to
/// it, its email codes, its own audit log, its keys, password and the
/// account itself. Entries about it in *other* accounts' audit logs stay:
/// they are the sender's own record, and the chain can't be edited.
/// Returns `false` if there is no such personal account.
pub async fn erase(db: &PgPool, org_id: &str) -> sqlx::Result<bool> {
    let mut tx = db.begin().await?;
    let email: Option<String> =
        sqlx::query_scalar("SELECT email FROM personal_accounts WHERE org_id = $1 FOR UPDATE")
            .bind(org_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some(email) = email else {
        return Ok(false);
    };
    // Waits for any audit append in progress for this account.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(org_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL svx.erasure = 'on'")
        .execute(&mut *tx)
        .await?;
    let steps: &[&str] = &[
        "DELETE FROM opens WHERE recipient = $1 \
           OR artifact_id IN (SELECT artifact_id FROM personal_files WHERE sender = $1)",
        "DELETE FROM approvals WHERE requester = $1",
        "DELETE FROM personal_file_recipients WHERE recipient = $1",
        // Cascades to the files' recipients and approvals.
        "DELETE FROM personal_files WHERE sender = $1",
        "DELETE FROM revocations WHERE revoked_by_org = $1",
        "DELETE FROM release_txns WHERE org_id = $1",
        "DELETE FROM audit WHERE org_id = $1",
        "DELETE FROM announcement_recipients WHERE org_id = $1",
        // Cascades to personal_accounts, email_accounts, org_keys,
        // org_admins and policies.
        "DELETE FROM orgs WHERE org_id = $1 AND kind = 'personal'",
    ];
    for sql in steps {
        sqlx::query(sql).bind(org_id).execute(&mut *tx).await?;
    }
    // Copies of emails to it, or naming it (e.g. "… is asking to open").
    sqlx::query(
        "DELETE FROM notifications WHERE lower(to_email) = lower($1) \
         OR strpos(lower(subject || ' ' || body), lower($1)) > 0",
    )
    .bind(&email)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM email_challenges WHERE email_lc = lower($1)")
        .bind(&email)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO admin_log (at, action, org_id) VALUES ($1, 'erased', $2)")
        .bind(unix_now())
        .bind(org_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}

/// Record something the operator did (account IDs only, never addresses).
pub async fn log_action(
    db: &PgPool,
    action: &str,
    org_id: Option<&str>,
    detail: Option<&str>,
) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO admin_log (at, action, org_id, detail) VALUES ($1, $2, $3, $4)")
        .bind(unix_now())
        .bind(action)
        .bind(org_id)
        .bind(detail)
        .execute(db)
        .await?;
    Ok(())
}

/// Turn announcement emails off or on for an account (it replied
/// "unsubscribe", or changed its mind). Returns `false` if nothing changed.
pub async fn set_announcements_off(db: &PgPool, org_id: &str, off: bool) -> sqlx::Result<bool> {
    let changed = sqlx::query(
        "UPDATE personal_accounts SET announcements_off = $2 \
         WHERE org_id = $1 AND announcements_off <> $2",
    )
    .bind(org_id)
    .bind(off)
    .execute(db)
    .await?
    .rows_affected()
        == 1;
    if changed {
        let action = if off {
            "announcements_off"
        } else {
            "announcements_on"
        };
        log_action(db, action, Some(org_id), None).await?;
    }
    Ok(changed)
}

/// Emails in the last 24 hours, against the mail account's allowance.
#[derive(Debug, serde::Serialize)]
pub struct EmailUsage {
    pub used: i64,
    pub announcements: i64,
    /// The mail account's allowance.
    pub limit: i64,
    /// Announcements stop at this many emails of any kind.
    pub announce_ceiling: i64,
    /// How many announcement emails could go out right now.
    pub announce_room: i64,
    /// Every email of the last 24 hours by kind: `code` (sign-up, sign-in,
    /// new device and password-reset codes), `notice` (approval and copy
    /// requests), `admin` (suspended, restored, deleted), `announcement`,
    /// `test`, `alert` (server health check), `welcome` (new accounts).
    pub by_kind: std::collections::BTreeMap<String, i64>,
}

pub async fn email_usage(db: &PgPool) -> sqlx::Result<EmailUsage> {
    use crate::limits::{ANNOUNCE_CEILING, MAIL_DAILY, emails_by_kind, emails_last_day};
    let (used, announcements) = emails_last_day(db).await?;
    Ok(EmailUsage {
        used,
        announcements,
        limit: MAIL_DAILY,
        announce_ceiling: ANNOUNCE_CEILING,
        announce_room: (ANNOUNCE_CEILING - used).max(0),
        by_kind: emails_by_kind(db).await?.into_iter().collect(),
    })
}

/// One line of the operator's logs page: an event from an account's audit
/// log, or something the operator did. No file names exist on the service.
#[derive(Debug, serde::Serialize, FromRow)]
pub struct LogEntry {
    pub at: i64,
    /// `account` (the account's own log) or `admin` (the operator).
    pub source: String,
    pub account: Option<String>,
    /// `None` once the account is erased.
    pub email: Option<String>,
    pub event: String,
    /// The other person, for events about someone else.
    pub subject: Option<String>,
    pub artifact_id: Option<String>,
    pub reason: Option<String>,
}

/// Events shown with "problems only".
pub const PROBLEM_EVENTS: &[&str] = &[
    audit::event::AUTHN_FAILURE,
    audit::event::AUTHZ_FAILURE,
    audit::event::SIGNATURE_FAILURE,
    audit::event::ARTIFACT_EXPIRED,
    audit::event::REVOKED_ACCESS,
    audit::event::REPLAY,
    audit::event::KEY_RELEASE_FAILURE,
    audit::event::SUSPICIOUS,
    audit::event::ADMIN_AUTH_FAILURE,
    audit::event::APPROVAL_DECLINED,
    audit::event::SHARE_DECLINED,
    audit::event::ACCOUNT_SUSPENDED,
];

#[derive(Debug, Default, Clone)]
pub struct LogFilter {
    /// Part of an email address or account ID.
    pub search: Option<String>,
    pub event: Option<String>,
    pub problems_only: bool,
    pub offset: i64,
    pub limit: i64,
}

/// Newest first: every account's audit log and the operator's actions.
pub async fn logs(db: &PgPool, f: &LogFilter) -> sqlx::Result<Vec<LogEntry>> {
    let search = f
        .search
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            let e = s
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            format!("%{}%", e.to_lowercase())
        });
    let problems: Vec<String> = PROBLEM_EVENTS.iter().map(|s| s.to_string()).collect();
    sqlx::query_as::<_, LogEntry>(
        "SELECT x.at, x.source, x.org_id AS account, p.email, x.event, x.subject, \
                x.artifact_id, x.reason \
         FROM ( \
           SELECT at, 'account' AS source, org_id, event, subject, artifact_id, reason, seq AS n \
           FROM audit \
           UNION ALL \
           SELECT at, 'admin', org_id, action, NULL, NULL, detail, id FROM admin_log \
         ) x LEFT JOIN personal_accounts p ON p.org_id = x.org_id \
         WHERE ($1::text IS NULL OR lower(coalesce(p.email, '')) LIKE $1 \
                OR coalesce(x.org_id, '') LIKE $1 OR lower(coalesce(x.subject, '')) LIKE $1) \
           AND ($2::text IS NULL OR x.event = $2) \
           AND (NOT $3 OR x.event = ANY($4)) \
         ORDER BY x.at DESC, x.source, x.n DESC LIMIT $5 OFFSET $6",
    )
    .bind(search)
    .bind(f.event.as_deref().filter(|e| !e.is_empty()))
    .bind(f.problems_only)
    .bind(&problems)
    .bind(f.limit.clamp(1, 500))
    .bind(f.offset.max(0))
    .fetch_all(db)
    .await
}

/// What the operator did to an account, for the email to its owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notice {
    Suspended,
    Unsuspended,
    Erased,
}

/// The email telling an account's owner what the operator did. The reason
/// is included only when one was given. No links, like every SVX email.
pub fn notice_email(notice: Notice, u: &User, reason: Option<&str>) -> Email {
    let hello = match u.first_name.as_deref().map(str::trim) {
        Some(n) if !n.is_empty() => format!("Hello {n},"),
        _ => "Hello,".to_owned(),
    };
    let reason = reason
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .map(|r| format!("Reason: {r}\n\n"))
        .unwrap_or_default();
    let (subject, what, more) = match notice {
        Notice::Suspended => (
            "Your SVX account has been suspended",
            "has been suspended",
            "While it is suspended you can't sign in or send files, nobody can send \
             you new files, and files you sent can't be opened. Nothing has been \
             deleted: if the suspension is lifted, everything works again.",
        ),
        Notice::Unsuspended => (
            "Your SVX account is active again",
            "is active again",
            "You can sign in and send files as before, and files you sent can be \
             opened again (unless they have expired or you revoked them).",
        ),
        Notice::Erased => (
            "Your SVX account has been deleted",
            "has been deleted",
            "Your account, its keys and every file you sent have been erased. \
             Files you sent can't be opened by anyone any more, and this can't \
             be undone. You can sign up again with this address at any time.",
        ),
    };
    Email {
        html: None,
        to: u.email.clone(),
        subject: subject.to_owned(),
        body: format!(
            "{hello}\n\nYour SVX account ({}) {what}.\n\n{reason}{more}\n\n\
             If you have a question or think this is a mistake, write to \
             support@getsvx.me.\n\nSVX\n",
            u.email
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice() -> User {
        User {
            org_id: "u.0123456789abcdef".into(),
            email: "alice@example.com".into(),
            first_name: Some("Alice".into()),
            last_name: Some("Example".into()),
            issuer: "svx:email".into(),
            created_at: 0,
            suspended_at: None,
            suspended_reason: None,
            last_active: None,
            announcements_off: false,
        }
    }

    #[test]
    fn the_reason_is_in_the_email_only_when_given() {
        let e = notice_email(Notice::Suspended, &alice(), Some(" spam reports "));
        assert_eq!(e.to, "alice@example.com");
        assert_eq!(e.subject, "Your SVX account has been suspended");
        assert!(e.body.starts_with("Hello Alice,"));
        assert!(e.body.contains("Reason: spam reports\n"));
        for reason in [None, Some("  ")] {
            let e = notice_email(Notice::Erased, &alice(), reason);
            assert!(!e.body.contains("Reason"), "{}", e.body);
            assert!(e.body.contains("has been deleted"));
        }
        let e = notice_email(
            Notice::Unsuspended,
            &User {
                first_name: None,
                ..alice()
            },
            None,
        );
        assert!(e.body.starts_with("Hello,\n") && e.body.contains("is active again"));
        assert!(!e.body.contains("http"));
    }
}
