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
    /// Plain text: the whole email, or the text alternative of `html`.
    pub body: String,
    /// An HTML version with inline images (the welcome email).
    pub html: Option<Html>,
}

/// The HTML part of an email; its images are attached inline and named in
/// the HTML as `cid:<cid>`, so nothing is fetched from a server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Html {
    pub body: String,
    pub images: Vec<InlineImage>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InlineImage {
    pub cid: &'static str,
    pub content_type: &'static str,
    pub data: &'static [u8],
}

/// A file attached to an email (announcements).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attachment {
    pub name: String,
    pub content_type: String,
    pub data: Vec<u8>,
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
    async fn send_now(&self, email: Email) -> anyhow::Result<()> {
        self.send_with_files(email, &[]).await
    }
    async fn send_with_files(&self, email: Email, files: &[Attachment]) -> anyhow::Result<()>;
}

/// Tests and the demo: keep emails in memory.
#[derive(Default)]
pub struct MemoryNotifier {
    sent: Mutex<Vec<Email>>,
    files: Mutex<Vec<Vec<Attachment>>>,
}

impl MemoryNotifier {
    pub fn sent(&self) -> Vec<Email> {
        self.sent.lock().expect("notifier lock").clone()
    }

    /// The attachments of each email in [`MemoryNotifier::sent`] (empty for
    /// emails sent without any).
    pub fn sent_files(&self) -> Vec<Vec<Attachment>> {
        let n = self.sent.lock().expect("notifier lock").len();
        let mut f = self.files.lock().expect("notifier lock").clone();
        f.resize(n, Vec::new());
        f
    }
}

impl Notifier for MemoryNotifier {
    fn deliver(&self, email: Email) {
        let mut sent = self.sent.lock().expect("notifier lock");
        let mut files = self.files.lock().expect("notifier lock");
        files.resize(sent.len(), Vec::new());
        sent.push(email);
        files.push(Vec::new());
    }
}

#[async_trait]
impl SendNow for MemoryNotifier {
    async fn send_with_files(&self, email: Email, files: &[Attachment]) -> anyhow::Result<()> {
        self.deliver(email);
        if let Some(last) = self.files.lock().expect("notifier lock").last_mut() {
            *last = files.to_vec();
        }
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
        self.message_with(email, &[])
    }

    fn message_with(&self, email: Email, files: &[Attachment]) -> anyhow::Result<Message> {
        use lettre::message::header::ContentType;
        use lettre::message::{MultiPart, SinglePart};
        let to: Mailbox = email
            .to
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid address: {e}"))?;
        let builder = Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(email.subject);
        if let Some(html) = email.html {
            // text + (HTML with its inline images)
            let mut related = MultiPart::related().singlepart(SinglePart::html(html.body));
            for img in html.images {
                related = related.singlepart(
                    lettre::message::Attachment::new_inline(img.cid.to_owned())
                        .body(img.data.to_vec(), ContentType::parse(img.content_type)?),
                );
            }
            let alt = MultiPart::alternative()
                .singlepart(SinglePart::plain(email.body))
                .multipart(related);
            return Ok(builder.multipart(alt)?);
        }
        if files.is_empty() {
            return Ok(builder.body(email.body)?);
        }
        let mut parts = MultiPart::mixed().singlepart(SinglePart::plain(email.body));
        for f in files {
            let kind = ContentType::parse(&f.content_type)
                .unwrap_or(ContentType::parse("application/octet-stream")?);
            parts = parts.singlepart(
                lettre::message::Attachment::new(f.name.clone()).body(f.data.clone(), kind),
            );
        }
        Ok(builder.multipart(parts)?)
    }
}

#[async_trait]
impl SendNow for SmtpNotifier {
    async fn send_with_files(&self, email: Email, files: &[Attachment]) -> anyhow::Result<()> {
        let message = self.message_with(email, files)?;
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
            if crate::limits::email_budget(st, crate::limits::MailKind::Notice).await {
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
