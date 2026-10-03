//! Emails to senders when someone asks to open their file. They name the
//! requester and the date only: no file names (the service never has them),
//! no contents and no links (approving happens only in the app).

use std::sync::Mutex;

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

impl Notifier for SmtpNotifier {
    fn deliver(&self, email: Email) {
        let to: Mailbox = match email.to.parse() {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = %e, "not sending to an invalid address");
                return;
            }
        };
        let message = match Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(email.subject)
            .body(email.body)
        {
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
        Ok(r) if r.rows_affected() == 1 => st.notifier.deliver(email),
        Ok(_) => {}
        Err(e) => tracing::error!(error = %e, "could not queue a notification"),
    }
}
