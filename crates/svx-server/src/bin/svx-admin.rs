//! `svx-admin`: operator commands for the SVX service, run on the server.
//!
//! ```sh
//! svx-admin stats
//! svx-admin users [--search alice] [--limit 50]
//! svx-admin user alice@example.com
//! svx-admin suspend alice@example.com [--reason "spam reports"]
//! svx-admin unsuspend alice@example.com
//! svx-admin delete alice@example.com --yes [--reason "asked to be removed"]
//! svx-admin web [--port 9790]   # admin page; started by scripts/admin.sh
//! svx-admin welcome-test you@example.com   # send yourself the welcome email
//! ```
//!
//! Reads `DATABASE_URL`. Accounts are named by email address or account ID.
//! Suspend, unsuspend and delete email the account's owner (with the reason,
//! if one is given) through `SVX_SMTP_URL` / `SVX_SMTP_FROM`, the service's
//! own email settings.

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use sqlx::PgPool;
use svx_server::admin_ops::{self, Notice, User};
use svx_server::notify::{SendNow, SmtpNotifier};

#[derive(Parser)]
#[command(name = "svx-admin", version, about = "SVX service operator commands")]
struct Args {
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: String,
    /// SMTP for telling account owners about suspensions and deletions.
    #[arg(
        long,
        env = "SVX_SMTP_URL",
        hide_env_values = true,
        requires = "smtp_from"
    )]
    smtp_url: Option<String>,
    #[arg(long, env = "SVX_SMTP_FROM")]
    smtp_from: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Counts: accounts, files, opens, database size.
    Stats,
    /// List accounts, newest first.
    Users {
        /// Match email, name or account ID.
        #[arg(long)]
        search: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: i64,
    },
    /// One account in detail.
    User { who: String },
    /// Stop an account: no sign-in, no requests, nobody can send it new
    /// files, and files it sent stop opening.
    Suspend {
        who: String,
        /// Included in the email to them.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Lift a suspension.
    Unsuspend { who: String },
    /// Erase an account and its data on request (cannot be undone).
    Delete {
        who: String,
        /// Confirm the erasure.
        #[arg(long)]
        yes: bool,
        /// Included in the email to them.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Serve the private admin page on 127.0.0.1 for an SSH port forward.
    /// Reads a one-time login token (64+ hex characters) from stdin and
    /// stops when stdin closes or after 30 minutes without a request.
    /// Started by `scripts/admin.sh` on the operator's Mac.
    Web {
        #[arg(long, default_value_t = 9790)]
        port: u16,
    },
    /// Send the welcome email new accounts get to an address, to see how
    /// it looks (counted as a test email).
    WelcomeTest {
        to: String,
        /// First name to greet (default: none, as for Google accounts).
        #[arg(long)]
        name: Option<String>,
    },
}

const WEB_IDLE: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// Record an admin-page action in the system journal (best effort).
fn journal(msg: &str) {
    eprintln!("{msg}");
    let _ = std::process::Command::new("logger")
        .args(["-t", "svx-admin", "--", msg])
        .status();
}

type Mail = Option<std::sync::Arc<dyn SendNow>>;

/// Email the account's owner and say whether it worked.
async fn tell(db: &PgPool, mail: &Mail, notice: Notice, u: &User, reason: Option<&str>) {
    let Some(mail) = mail else {
        println!("no email sent: SVX_SMTP_URL and SVX_SMTP_FROM aren't set");
        return;
    };
    use svx_server::limits::{MAIL_DAILY, MailKind, take_email};
    match take_email(db, MailKind::Admin, MAIL_DAILY).await {
        Ok(true) => {}
        Ok(false) => {
            println!("no email sent: today's email allowance is used up");
            return;
        }
        Err(e) => {
            println!("no email sent: couldn't count today's emails: {e}");
            return;
        }
    }
    match mail
        .send_now(admin_ops::notice_email(notice, u, reason))
        .await
    {
        Ok(()) => println!("emailed {}", u.email),
        Err(e) => println!("the email to {} couldn't be sent: {e}", u.email),
    }
}

fn given(r: &Option<String>) -> Option<&str> {
    r.as_deref().map(str::trim).filter(|r| !r.is_empty())
}

async fn web(db: PgPool, port: u16, mail: Mail) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
    let mut stdin = BufReader::new(tokio::io::stdin());
    let mut token = String::new();
    stdin
        .read_line(&mut token)
        .await
        .context("reading the login token from stdin")?;
    let app = svx_server::admin_web::AdminWeb::new(db, &token, journal, mail)?;
    token.clear();
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .with_context(|| format!("port {port} is busy (is another admin session open?)"))?;
    // The script waits for this line before opening the browser.
    println!("ready");
    let idle = app.clone();
    let stop = async move {
        let stdin_closed = async {
            let mut sink = [0u8; 256];
            while matches!(stdin.read(&mut sink).await, Ok(n) if n > 0) {}
        };
        let idle_out = async {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                if idle.idle_for() > WEB_IDLE {
                    break;
                }
            }
        };
        tokio::select! {
            _ = stdin_closed => eprintln!("session closed"),
            _ = idle_out => eprintln!("no activity for 30 minutes: session closed"),
        }
    };
    axum::serve(listener, app.router())
        .with_graceful_shutdown(stop)
        .await
        .context("serving the admin page")
}

fn when(t: Option<i64>) -> String {
    t.map(|t| {
        let days = t.div_euclid(86_400);
        let (y, m, d) = civil(days);
        format!("{y:04}-{m:02}-{d:02}")
    })
    .unwrap_or_else(|| "-".into())
}

/// Days since 1970-01-01 to a calendar date (proleptic Gregorian).
fn civil(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

async fn account(db: &PgPool, who: &str) -> Result<User> {
    admin_ops::find(db, who)
        .await?
        .with_context(|| format!("no personal account {who:?}"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let a = Args::parse();
    let db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&a.database_url)
        .await
        .context("connecting to Postgres")?;
    let mail: Mail = match (&a.smtp_url, &a.smtp_from) {
        (Some(url), Some(from)) => Some(std::sync::Arc::new(SmtpNotifier::new(url, from)?)),
        _ => None,
    };
    match a.cmd {
        Cmd::Web { port } => web(db, port, mail).await?,
        Cmd::WelcomeTest { to, name } => {
            use svx_server::limits::{ANNOUNCE_CEILING, MailKind, take_email};
            let Some(mail) = &mail else {
                bail!("SVX_SMTP_URL and SVX_SMTP_FROM aren't set");
            };
            if !take_email(&db, MailKind::Test, ANNOUNCE_CEILING).await? {
                bail!("today's email allowance for tests is used up");
            }
            let email = svx_server::welcome::welcome_email(to.trim(), name.as_deref());
            mail.send_now(email).await?;
            println!("sent the welcome email to {}", to.trim());
        }
        Cmd::Stats => println!("{}", admin_ops::stats(&db).await?),
        Cmd::Users { search, limit } => {
            let list = admin_ops::users(&db, search.as_deref(), limit).await?;
            println!(
                "{:<36} {:<24} {:<20} {:<7} {:<10} {:<10} STATUS",
                "EMAIL", "NAME", "ACCOUNT", "SIGN-IN", "CREATED", "ACTIVE"
            );
            for u in &list {
                println!(
                    "{:<36} {:<24} {:<20} {:<7} {:<10} {:<10} {}",
                    u.email,
                    u.name(),
                    u.org_id,
                    u.sign_in(),
                    when(Some(u.created_at)),
                    when(u.last_active),
                    if u.suspended_at.is_some() {
                        "suspended"
                    } else {
                        "ok"
                    }
                );
            }
            println!("{} shown", list.len());
        }
        Cmd::User { who } => {
            let u = account(&db, &who).await?;
            let act = admin_ops::activity(&db, &u.org_id).await?;
            println!("email          {}", u.email);
            println!("name           {}", u.name());
            println!("account        {}", u.org_id);
            println!("sign-in        {}", u.sign_in());
            println!("created        {}", when(Some(u.created_at)));
            println!("last active    {}", when(u.last_active));
            match u.suspended_at {
                Some(t) => println!(
                    "status         suspended {} ({})",
                    when(Some(t)),
                    u.suspended_reason.as_deref().unwrap_or("")
                ),
                None => println!("status         ok"),
            }
            println!("files sent     {}", act.files_sent);
            println!("files received {}", act.files_received);
            println!("opens          {}", act.opens);
            println!("pending        {} approval requests", act.pending_approvals);
            println!("active keys    {}", act.active_keys);
        }
        Cmd::Suspend { who, reason } => {
            let u = account(&db, &who).await?;
            let reason = given(&reason);
            if admin_ops::suspend(&db, &u.org_id, reason).await? {
                println!("suspended {} ({})", u.email, u.org_id);
                tell(&db, &mail, Notice::Suspended, &u, reason).await;
            } else {
                println!("{} was already suspended", u.email);
            }
        }
        Cmd::Unsuspend { who } => {
            let u = account(&db, &who).await?;
            if admin_ops::unsuspend(&db, &u.org_id).await? {
                println!("{} ({}) can use SVX again", u.email, u.org_id);
                tell(&db, &mail, Notice::Unsuspended, &u, None).await;
            } else {
                println!("{} was not suspended", u.email);
            }
        }
        Cmd::Delete { who, yes, reason } => {
            let u = account(&db, &who).await?;
            if !yes {
                bail!(
                    "this erases {} ({}) and every file they sent, for good; add --yes to confirm",
                    u.email,
                    u.org_id
                );
            }
            if admin_ops::erase(&db, &u.org_id).await? {
                println!("erased {} ({})", u.email, u.org_id);
                tell(&db, &mail, Notice::Erased, &u, given(&reason)).await;
            } else {
                bail!("{} disappeared before it could be erased", u.email);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn dates() {
        assert_eq!(super::civil(0), (1970, 1, 1));
        assert_eq!(super::civil(20_731), (2026, 10, 5));
        assert_eq!(super::civil(11_016), (2000, 2, 29));
    }
}
