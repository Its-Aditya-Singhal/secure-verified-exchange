//! `svx-demo`: the Acme Security → Example Corp walkthrough, and a
//! one-command local stack for trying the CLI and SDKs.
//!
//! Both modes start the real managed service, Example Corp's key agent and
//! two development IdPs in-process on loopback, backed by two fresh
//! PostgreSQL databases that are dropped on exit. All organizations and
//! people are fictional.

#![forbid(unsafe_code)]

mod scenarios;
mod ui;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use svx_testkit::World;

#[derive(Parser)]
#[command(name = "svx-demo", version, about)]
struct Cli {
    /// PostgreSQL URL with CREATE DATABASE rights; two temporary databases
    /// are created and dropped again.
    #[arg(
        long,
        env = "DATABASE_URL",
        default_value = "postgres://svx:svx@127.0.0.1:5432/postgres",
        global = true
    )]
    database_url: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the scripted scenarios and check every outcome.
    Run {
        /// Working directory for files (default: a temporary directory).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Keep the working directory.
        #[arg(long)]
        keep: bool,
        /// Only print the summary.
        #[arg(long)]
        quiet: bool,
        /// Disable colors (also honors NO_COLOR).
        #[arg(long)]
        no_color: bool,
    },
    /// Start the stack, write state.json and client configs to DIR, and
    /// run until interrupted.
    Serve {
        #[arg(long)]
        state_dir: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("svx-demo: {e:#}");
            ExitCode::from(2)
        }
    }
}

async fn start(database_url: &str) -> Result<World> {
    // World panics on setup failures; check connectivity first for a clear error.
    svx_testkit::check_database(database_url)
        .await
        .with_context(|| format!("connecting to PostgreSQL at {}", redact(database_url)))?;
    Ok(World::connect(database_url, "demo").await)
}

fn redact(url: &str) -> String {
    match url.split_once('@') {
        Some((scheme_user, host)) => match scheme_user.rsplit_once(':') {
            Some((su, _)) if su.contains("//") && !su.ends_with('/') => format!("{su}:***@{host}"),
            _ => url.to_owned(),
        },
        None => url.to_owned(),
    }
}

async fn run(cli: Cli) -> Result<ExitCode> {
    match cli.cmd {
        Cmd::Run {
            out,
            keep,
            quiet,
            no_color,
        } => {
            let color = !no_color && std::env::var_os("NO_COLOR").is_none() && ui::is_tty();
            let ui = ui::Ui::new(color, quiet);
            let (dir, _tmp) = match out {
                Some(d) => {
                    std::fs::create_dir_all(&d)?;
                    (d, None)
                }
                None => {
                    let t = tempfile::Builder::new().prefix("svx-demo-").tempdir()?;
                    (t.path().to_path_buf(), Some(t))
                }
            };
            ui.banner("Starting the SVX demo stack (managed service, key agent, two IdPs)...");
            let world = start(&cli.database_url).await?;
            let outcome = scenarios::run_all(&world, &dir, &ui).await;
            world.cleanup().await.context("dropping demo databases")?;
            outcome?;
            let ok = ui.summary();
            if keep {
                if let Some(t) = _tmp {
                    let p = t.keep();
                    println!("Files kept in {}", p.display());
                } else {
                    println!("Files in {}", dir.display());
                }
            }
            Ok(if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        Cmd::Serve { state_dir } => {
            let world = start(&cli.database_url).await?;
            let state = world.write_state(&state_dir)?;
            let example_cfg = &state.orgs[1].config;
            let acme_cfg = &state.orgs[0].config;
            println!("SVX dev stack is running (fictional organizations, dev logins).");
            println!("  Service:        {}", state.service_url);
            println!("  Key agent:      {}", state.agent_url);
            for o in &state.orgs {
                let users: Vec<_> = o.users.iter().map(|u| u.sub.as_str()).collect();
                println!(
                    "  {:<15} IdP {} users: {}",
                    o.org_id,
                    o.idp_issuer,
                    users.join(", ")
                );
            }
            println!("  Registry key fingerprint: {}", state.registry_key);
            println!(
                "  State:          {}",
                state_dir.join("state.json").display()
            );
            println!();
            println!("Try:");
            println!(
                "  svx --config {} open {} -o /tmp/svx-out --dev-user alice",
                example_cfg.display(),
                state.sample_artifact.display()
            );
            println!(
                "  svx --config {} open {} -o /tmp/svx-out --dev-user bob",
                example_cfg.display(),
                state.sample_artifact.display()
            );
            println!(
                "  svx --config {} pack report.txt --recipient example-corp --policy {} --sign-key {}",
                acme_cfg.display(),
                state.policy,
                state.acme_signing_key.display()
            );
            println!();
            println!("Press Ctrl-C to stop (databases are dropped on exit).");
            // Signal readiness to wrappers (SDK test fixtures) on its own line.
            println!("SVX_DEMO_READY");
            wait_for_shutdown().await;
            world.cleanup().await.context("dropping demo databases")?;
            let _ = std::fs::remove_file(state_dir.join("state.json"));
            eprintln!("Stopped.");
            Ok(ExitCode::SUCCESS)
        }
    }
}

async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::redact;

    #[test]
    fn redacts_password() {
        assert_eq!(
            redact("postgres://svx:secret@db:5432/postgres"),
            "postgres://svx:***@db:5432/postgres"
        );
        assert_eq!(
            redact("postgres://svx@db/postgres"),
            "postgres://svx@db/postgres"
        );
    }
}
