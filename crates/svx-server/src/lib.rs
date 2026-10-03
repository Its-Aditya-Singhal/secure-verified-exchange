//! The SVX managed service.
//!
//! Responsibilities (see `docs/architecture.md`):
//!
//! * organization registry with DNS domain verification and signed records;
//! * per-organization IdP configuration, admins, keys and policies;
//! * the key-release decision: artifact verification, user authentication
//!   via the recipient org's IdP, policy, expiry, revocation and replay
//!   checks, then release of the **service** share only;
//! * an append-only, hash-chained audit log.
//!
//! The service never holds the recipient organization's share and never
//! sees payloads.

#![forbid(unsafe_code)]

pub mod audit;
pub mod db;
pub mod dns;
pub mod error;
pub mod keys;
pub mod notify;
pub mod policy;
mod routes;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use svx_core::format::Identifier;
use svx_oidc::Validator;
use svx_protocol::personal::PersonalIdp;

pub use routes::router;

/// Maximum request body (a release request carries a ≤1 MiB header, base64).
pub const MAX_BODY: usize = 3 * 1024 * 1024;
/// Lifetime of a release grant.
pub const GRANT_TTL_SECS: i64 = 60;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub service_id: Identifier,
    pub keys: Arc<dyn keys::KeyProvider>,
    pub oidc: Arc<Validator>,
    pub dns: Arc<dyn dns::DnsVerifier>,
    /// Sign-in providers for personal accounts (Google, Apple).
    pub personal_idps: Arc<Vec<PersonalIdp>>,
    /// Sends approval-request emails.
    pub notifier: Arc<dyn notify::Notifier>,
    pub limiter: Arc<RateLimiter>,
    /// Allows plain-http loopback IdPs and key agents. Never in production.
    pub dev: bool,
}

/// A fixed-window per-key rate limit (in memory, per process).
#[derive(Default)]
pub struct RateLimiter {
    windows: Mutex<HashMap<String, (i64, u32)>>,
}

impl RateLimiter {
    /// Whether `key` may make another call this minute (at most `per_minute`).
    pub fn allow(&self, key: &str, per_minute: u32) -> bool {
        let minute = svx_protocol::unix_now() / 60;
        let mut w = self.windows.lock().expect("rate limiter lock");
        if w.len() > 100_000 {
            w.retain(|_, (m, _)| *m == minute);
        }
        let e = w.entry(key.to_owned()).or_insert((minute, 0));
        if e.0 != minute {
            *e = (minute, 0);
        }
        e.1 += 1;
        e.1 <= per_minute
    }
}

/// Apply migrations and build the router.
pub async fn app(state: AppState) -> anyhow::Result<Router> {
    sqlx::migrate!("./migrations").run(&state.db).await?;
    Ok(router(state))
}
