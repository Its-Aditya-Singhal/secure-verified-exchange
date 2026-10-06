//! Emails to senders when someone asks to open their file. They name the
//! requester and the date only: no file names (the service never has them),
//! no contents and no links (approving happens only in the app).

use std::sync::Mutex;

use async_trait::async_trait;
use lettre::message::Mailbox;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::AppState;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Email {
    pub to: String,
    pub subject: String,
    pub body: String,
}

/// Delivers emails. Implementations must not block: send in the background.
pub trait Notifier: Send + Sync {
    fn deliver(&self, email: Email);
}

/// Development: log the email instead of sending it.
pub struct LogNotifier;

impl Notifier for LogNotifier {
    fn deliver(&self, email: Email) {
        tracing::info!(to = %email.to, subject = %email.subject, "notification (not sent: no SMTP configured)");
    }
}

/// Sends one email and waits for the answer. Used by `svx-admin`, which
/// tells the operator whether the account's owner was emailed.
#[async_trait]
pub trait SendNow: Send + Sync {
    async fn send_now(&self, email: Email) -> anyhow::Result<()>;
}

/// Tests and the demo: keep emails in memory.
#[derive(Default)]
pub struct MemoryNotifier {
    sent: Mutex<Vec<Email>>,
}

impl MemoryNotifier {
    pub fn sent(&self) -> Vec<Email> {
        self.sent.lock().expect("notifier lock").clone()
    }
}

impl Notifier for MemoryNotifier {
    fn deliver(&self, email: Email) {
        self.sent.lock().expect("notifier lock").push(email);
    }
}

#[async_trait]
impl SendNow for MemoryNotifier {
    async fn send_now(&self, email: Email) -> anyhow::Result<()> {
        self.deliver(email);
        Ok(())
    }
}

/// SMTP over TLS, e.g. `smtps://user:password@smtp.example.com:465`.
pub struct SmtpNotifier {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

impl SmtpNotifier {
    pub fn new(url: &str, from: &str) -> anyhow::Result<Self> {
        if !url.starts_with("smtps://") && !url.contains("tls=required") {
            anyhow::bail!("the SMTP URL must use TLS (smtps://… or ?tls=required)");
        }
        Ok(SmtpNotifier {
            transport: AsyncSmtpTransport::<Tokio1Executor>::from_url(url)?.build(),
            from: from.parse()?,
        })
    }
}

impl SmtpNotifier {
    fn message(&self, email: Email) -> anyhow::Result<Message> {
        let to: Mailbox = email
            .to
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid address: {e}"))?;
        Ok(Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(email.subject)
            .body(email.body)?)
    }
}

#[async_trait]
impl SendNow for SmtpNotifier {
    async fn send_now(&self, email: Email) -> anyhow::Result<()> {
        let message = self.message(email)?;
        self.transport.send(message).await?;
        Ok(())
    }
}

impl Notifier for SmtpNotifier {
    fn deliver(&self, email: Email) {
        let message = match self.message(email) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = %e, "could not build the email");
                return;
            }
        };
        let transport = self.transport.clone();
        tokio::spawn(async move {
            if let Err(e) = transport.send(message).await {
                tracing::warn!(error = %e, "email delivery failed");
            }
        });
    }
}

/// Queue an email once per `dedupe_key` and hand it to the notifier.
pub async fn queue(st: &AppState, dedupe_key: &str, email: Email) {
    let now = svx_protocol::unix_now();
    let inserted = sqlx::query(
        "INSERT INTO notifications (to_email, subject, body, dedupe_key, created_at, sent_at) \
         VALUES ($1, $2, $3, $4, $5, $5) ON CONFLICT (dedupe_key) DO NOTHING",
    )
    .bind(&email.to)
    .bind(&email.subject)
    .bind(&email.body)
    .bind(dedupe_key)
    .bind(now)
    .execute(&st.db)
    .await;
    match inserted {
        Ok(r) if r.rows_affected() == 1 => {
            if crate::limits::email_budget(st) {
                st.notifier.deliver(email);
            } else {
                // Over today's budget: keep it, marked unsent. The app
                // shows the request anyway.
                tracing::warn!("daily email budget used up: notification not sent");
                let _ =
                    sqlx::query("UPDATE notifications SET sent_at = NULL WHERE dedupe_key = $1")
                        .bind(dedupe_key)
                        .execute(&st.db)
                        .await;
            }
        }
        Ok(_) => {}
        Err(e) => tracing::error!(error = %e, "could not queue a notification"),
    }
}
