//! Announcements: emails from the operator (for example about a new
//! release) to chosen accounts, written in the admin page.
//!
//! Creating one only stores it; the service's worker ([`run`]) sends it,
//! one email per person (nobody sees the other recipients), within the
//! shared daily allowance: announcements stop at
//! [`ANNOUNCE_CEILING`](crate::limits::ANNOUNCE_CEILING) emails of any kind
//! in the last 24 hours, so sign-up codes and approval emails always have
//! room. With `queue_rest` the rest wait for the following days; without
//! it, only the people who fit today are added. Suspended and opted-out
//! accounts are skipped. Attachments are deleted once it is done.

use std::sync::Arc;
use std::time::Duration;

use sqlx::{FromRow, PgPool};
use svx_protocol::unix_now;

use crate::admin_ops;
use crate::limits::{ANNOUNCE_CEILING, MailKind, take_email};
use crate::notify::{Attachment, Email, SendNow};

pub const MAX_FILES: usize = 5;
/// All attachments together (Gmail takes 25 MB, base64 adds a third).
pub const MAX_FILES_BYTES: usize = 10 * 1024 * 1024;
pub const MAX_SUBJECT: usize = 200;
pub const MAX_BODY: usize = 20_000;

/// Added to every announcement.
pub const FOOTER: &str = "\n\n--\nYou get this because you have an SVX account. \
Don't want these emails? Reply \"unsubscribe\" or write to support@getsvx.me.\n";

/// What the operator wrote.
#[derive(Clone, Debug)]
pub struct Draft {
    pub subject: String,
    pub body: String,
    pub files: Vec<Attachment>,
}

impl Draft {
    /// Trimmed and checked; the reason is shown to the operator.
    pub fn check(mut self) -> Result<Draft, &'static str> {
        self.subject = self.subject.trim().to_owned();
        self.body = self.body.trim_end().to_owned();
        if self.subject.is_empty() || self.subject.chars().count() > MAX_SUBJECT {
            return Err("write a subject (up to 200 characters)");
        }
        if self.subject.contains(['\r', '\n']) {
            return Err("the subject must be one line");
        }
        if self.body.trim().is_empty() || self.body.chars().count() > MAX_BODY {
            return Err("write a message (up to 20,000 characters)");
        }
        if self.files.len() > MAX_FILES {
            return Err("attach at most 5 files");
        }
        if self.files.iter().map(|f| f.data.len()).sum::<usize>() > MAX_FILES_BYTES {
            return Err("attachments can be 10 MB in total at most");
        }
        for f in &mut self.files {
            f.name = clean_name(&f.name);
            if f.data.is_empty() {
                return Err("an attached file is empty");
            }
            if f.content_type
                .parse::<lettre::message::header::ContentType>()
                .is_err()
            {
                f.content_type = "application/octet-stream".into();
            }
        }
        Ok(self)
    }

    fn email_to(&self, to: &str) -> Email {
        Email {
            to: to.to_owned(),
            subject: self.subject.clone(),
            body: format!("{}{FOOTER}", self.body),
        }
    }
}

/// A file name safe to put in an email header.
fn clean_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let s: String = base
        .chars()
        .filter(|c| !c.is_control() && *c != '"')
        .take(120)
        .collect();
    let s = s.trim().to_owned();
    if s.is_empty() || s == "." || s == ".." {
        "attachment".into()
    } else {
        s
    }
}

/// What [`create`] did.
#[derive(Debug, serde::Serialize)]
pub struct Created {
    pub id: i64,
    /// Will be sent (now, or over the next days when queued).
    pub recipients: i64,
    /// Chosen but suspended or opted out.
    pub skipped: i64,
    /// Chosen but left out: no room today and not queued.
    pub left_out: i64,
    /// How many of the recipients fit in today's allowance.
    pub today: i64,
}

/// Store an announcement for the worker. `accounts` are account IDs.
pub async fn create(
    db: &PgPool,
    draft: Draft,
    accounts: &[String],
    queue_rest: bool,
) -> anyhow::Result<Created> {
    let mut eligible: Vec<(String, String)> = sqlx::query_as(
        "SELECT p.org_id, p.email FROM personal_accounts p JOIN orgs o ON o.org_id = p.org_id \
         WHERE p.org_id = ANY($1) AND o.suspended_at IS NULL AND NOT p.announcements_off \
         ORDER BY p.created_at, p.org_id",
    )
    .bind(accounts)
    .fetch_all(db)
    .await?;
    let mut chosen = accounts.to_vec();
    chosen.sort();
    chosen.dedup();
    let skipped = chosen.len() as i64 - eligible.len() as i64;
    let room = admin_ops::email_usage(db).await?.announce_room;
    let mut left_out = 0;
    if !queue_rest && eligible.len() as i64 > room {
        left_out = eligible.len() as i64 - room;
        eligible.truncate(room as usize);
    }
    if eligible.is_empty() {
        anyhow::bail!(if left_out > 0 {
            "no announcement emails can go out today: try again tomorrow or queue them"
        } else {
            "none of the chosen people can get announcements (suspended or opted out)"
        });
    }

    let mut tx = db.begin().await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO announcements (created_at, subject, body, status, queue_rest) \
         VALUES ($1, $2, $3, 'sending', $4) RETURNING id",
    )
    .bind(unix_now())
    .bind(&draft.subject)
    .bind(&draft.body)
    .bind(queue_rest)
    .fetch_one(&mut *tx)
    .await?;
    for f in &draft.files {
        sqlx::query(
            "INSERT INTO announcement_files (announcement_id, name, content_type, data) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(id)
        .bind(&f.name)
        .bind(&f.content_type)
        .bind(&f.data)
        .execute(&mut *tx)
        .await?;
    }
    for (org, email) in &eligible {
        sqlx::query(
            "INSERT INTO announcement_recipients (announcement_id, org_id, email, state) \
             VALUES ($1, $2, $3, 'pending')",
        )
        .bind(id)
        .bind(org)
        .bind(email)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("INSERT INTO admin_log (at, action, detail) VALUES ($1, 'announcement', $2)")
        .bind(unix_now())
        .bind(format!(
            "#{id} to {} people: {}",
            eligible.len(),
            draft.subject
        ))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let recipients = eligible.len() as i64;
    Ok(Created {
        id,
        recipients,
        skipped,
        left_out,
        today: recipients.min(room),
    })
}

/// Send the draft to one address now (the operator's test), counted in the
/// allowance like an announcement.
pub async fn send_test(
    db: &PgPool,
    mail: &dyn SendNow,
    draft: &Draft,
    to: &str,
) -> anyhow::Result<()> {
    if !take_email(db, MailKind::Test, ANNOUNCE_CEILING).await? {
        anyhow::bail!("today's allowance for announcements is used up");
    }
    admin_ops::log_action(db, "announcement_test", None, Some(&draft.subject)).await?;
    mail.send_with_files(draft.email_to(to), &draft.files).await
}

/// Stop sending: whoever hasn't got it yet won't.
pub async fn stop(db: &PgPool, id: i64) -> sqlx::Result<bool> {
    let mut tx = db.begin().await?;
    let changed = sqlx::query(
        "UPDATE announcements SET status = 'stopped' WHERE id = $1 AND status = 'sending'",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    if changed {
        sqlx::query(
            "UPDATE announcement_recipients SET state = 'stopped', done_at = $2 \
             WHERE announcement_id = $1 AND state = 'pending'",
        )
        .bind(id)
        .bind(unix_now())
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM announcement_files WHERE announcement_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO admin_log (at, action, detail) VALUES ($1, 'announcement_stopped', $2)",
        )
        .bind(unix_now())
        .bind(format!("#{id}"))
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(changed)
}

/// One announcement for the history list.
#[derive(Debug, serde::Serialize, FromRow)]
pub struct Summary {
    pub id: i64,
    pub created_at: i64,
    pub subject: String,
    pub status: String,
    pub queue_rest: bool,
    pub sent: i64,
    pub pending: i64,
    pub failed: i64,
    pub skipped: i64,
    pub stopped: i64,
    pub files: i64,
}

pub async fn list(db: &PgPool, limit: i64) -> sqlx::Result<Vec<Summary>> {
    sqlx::query_as::<_, Summary>(
        "SELECT a.id, a.created_at, a.subject, a.status, a.queue_rest, \
           (SELECT count(*) FROM announcement_recipients r WHERE r.announcement_id = a.id AND r.state = 'sent') AS sent, \
           (SELECT count(*) FROM announcement_recipients r WHERE r.announcement_id = a.id AND r.state = 'pending') AS pending, \
           (SELECT count(*) FROM announcement_recipients r WHERE r.announcement_id = a.id AND r.state = 'failed') AS failed, \
           (SELECT count(*) FROM announcement_recipients r WHERE r.announcement_id = a.id AND r.state = 'skipped') AS skipped, \
           (SELECT count(*) FROM announcement_recipients r WHERE r.announcement_id = a.id AND r.state = 'stopped') AS stopped, \
           (SELECT count(*) FROM announcement_files f WHERE f.announcement_id = a.id) AS files \
         FROM announcements a ORDER BY a.id DESC LIMIT $1",
    )
    .bind(limit.clamp(1, 200))
    .fetch_all(db)
    .await
}

#[derive(FromRow)]
struct Pending {
    announcement_id: i64,
    org_id: String,
    email: String,
    subject: String,
    body: String,
}

/// Send up to `max` waiting emails, oldest announcement first, while the
/// allowance lasts. Returns how many were sent.
pub async fn send_pending(db: &PgPool, mail: &dyn SendNow, max: i64) -> anyhow::Result<usize> {
    let batch: Vec<Pending> = sqlx::query_as(
        "SELECT r.announcement_id, r.org_id, r.email, a.subject, a.body \
         FROM announcement_recipients r JOIN announcements a ON a.id = r.announcement_id \
         WHERE r.state = 'pending' AND a.status = 'sending' \
         ORDER BY r.announcement_id, r.org_id LIMIT $1",
    )
    .bind(max)
    .fetch_all(db)
    .await?;
    let mut sent = 0;
    let mut files: Option<(i64, Vec<Attachment>)> = None;
    for p in &batch {
        // Still allowed? (Suspended or opted out since it was written.)
        let ok: Option<bool> = sqlx::query_scalar(
            "SELECT o.suspended_at IS NULL AND NOT p.announcements_off \
             FROM personal_accounts p JOIN orgs o ON o.org_id = p.org_id WHERE p.org_id = $1",
        )
        .bind(&p.org_id)
        .fetch_optional(db)
        .await?;
        if ok != Some(true) {
            mark(db, p, "skipped", None).await?;
            continue;
        }
        if !take_email(db, MailKind::Announcement, ANNOUNCE_CEILING).await? {
            break;
        }
        if files
            .as_ref()
            .is_none_or(|(id, _)| *id != p.announcement_id)
        {
            let f: Vec<(String, String, Vec<u8>)> = sqlx::query_as(
                "SELECT name, content_type, data FROM announcement_files \
                 WHERE announcement_id = $1 ORDER BY id",
            )
            .bind(p.announcement_id)
            .fetch_all(db)
            .await?;
            let f = f
                .into_iter()
                .map(|(name, content_type, data)| Attachment {
                    name,
                    content_type,
                    data,
                })
                .collect();
            files = Some((p.announcement_id, f));
        }
        let draft = Draft {
            subject: p.subject.clone(),
            body: p.body.clone(),
            files: Vec::new(),
        };
        let attached = files.as_ref().map(|(_, f)| f.as_slice()).unwrap_or(&[]);
        match mail
            .send_with_files(draft.email_to(&p.email), attached)
            .await
        {
            Ok(()) => {
                mark(db, p, "sent", None).await?;
                sent += 1;
            }
            Err(e) => {
                tracing::warn!(error = %e, announcement = p.announcement_id, "announcement email failed");
                mark(db, p, "failed", Some(&e.to_string())).await?;
            }
        }
    }
    finish(db).await?;
    Ok(sent)
}

async fn mark(db: &PgPool, p: &Pending, state: &str, error: Option<&str>) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE announcement_recipients SET state = $3, done_at = $4, error = $5 \
         WHERE announcement_id = $1 AND org_id = $2",
    )
    .bind(p.announcement_id)
    .bind(&p.org_id)
    .bind(state)
    .bind(unix_now())
    .bind(error.map(|e| e.chars().take(300).collect::<String>()))
    .execute(db)
    .await?;
    Ok(())
}

/// Close announcements with nobody left to send to, and drop their files.
async fn finish(db: &PgPool) -> sqlx::Result<()> {
    let done: Vec<i64> = sqlx::query_scalar(
        "UPDATE announcements a SET status = 'done' WHERE status = 'sending' AND NOT EXISTS \
         (SELECT 1 FROM announcement_recipients r WHERE r.announcement_id = a.id AND r.state = 'pending') \
         RETURNING id",
    )
    .fetch_all(db)
    .await?;
    if !done.is_empty() {
        sqlx::query("DELETE FROM announcement_files WHERE announcement_id = ANY($1)")
            .bind(&done)
            .execute(db)
            .await?;
    }
    Ok(())
}

/// The service's worker: sends waiting announcement emails every 15
/// seconds and forgets email counts older than a week.
pub async fn run(db: PgPool, mail: Arc<dyn SendNow>) {
    let mut tick = tokio::time::interval(Duration::from_secs(15));
    let mut rounds: u64 = 0;
    loop {
        tick.tick().await;
        if let Err(e) = send_pending(&db, mail.as_ref(), 20).await {
            tracing::error!(error = %e, "sending announcements");
        }
        if rounds.is_multiple_of(240) {
            let week = unix_now() - 7 * 86_400;
            if let Err(e) = sqlx::query("DELETE FROM email_sends WHERE at < $1")
                .bind(week)
                .execute(&db)
                .await
            {
                tracing::error!(error = %e, "pruning the email count");
            }
        }
        rounds += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drafts_are_checked() {
        let d = |subject: &str, body: &str| Draft {
            subject: subject.into(),
            body: body.into(),
            files: vec![],
        };
        assert!(d("  ", "hello").check().is_err());
        assert!(d("New\nline", "hello").check().is_err());
        assert!(d("Version 0.2", " ").check().is_err());
        let ok = d("  Version 0.2 is out ", "Hello,\n\nnew things.\n\n")
            .check()
            .unwrap();
        assert_eq!(ok.subject, "Version 0.2 is out");
        let e = ok.email_to("alice@example.com");
        assert!(e.body.starts_with("Hello,\n\nnew things.\n\n--\n"));
        assert!(e.body.contains("unsubscribe"));
    }

    #[test]
    fn attachment_names_are_cleaned() {
        assert_eq!(clean_name("../../etc/passwd"), "passwd");
        assert_eq!(clean_name("C:\\docs\\notes \"v2\".pdf"), "notes v2.pdf");
        assert_eq!(clean_name(".."), "attachment");
        assert_eq!(clean_name("a\r\nb.txt"), "ab.txt");
    }
}
