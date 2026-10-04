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
    /// Sign-in providers for personal accounts (Google).
    pub personal_idps: Arc<Vec<PersonalIdp>>,
    /// Sends approval-request emails.
    pub notifier: Arc<dyn notify::Notifier>,
    pub limiter: Arc<RateLimiter>,
    /// Recently signed registry records (SLH-DSA signing takes a fraction
    /// of a second, so unchanged records are not signed on every request).
    pub records: Arc<RecordCache>,
    /// Desktop app updates to publish (`--updates-dir`), if any.
    pub updates: Option<Arc<std::path::PathBuf>>,
    /// Allows plain-http loopback IdPs and key agents. Never in production.
    pub dev: bool,
}

/// Signed registry and service records, reused while their content is
/// unchanged and they are younger than [`RecordCache::REUSE_SECS`] (well
/// inside the clients' 15-minute freshness limit).
#[derive(Default)]
pub struct RecordCache {
    entries: Mutex<HashMap<String, CachedRecord>>,
}

struct CachedRecord {
    /// The record serialized with `issued_at` zeroed.
    content: Vec<u8>,
    issued_at: i64,
    signed: Vec<u8>,
}

impl RecordCache {
    pub const REUSE_SECS: i64 = 5 * 60;

    /// The cached signed record for `key`, if `content` is unchanged and it
    /// is still fresh at `now`.
    pub fn get(&self, key: &str, content: &[u8], now: i64) -> Option<Vec<u8>> {
        let e = self.entries.lock().expect("record cache lock");
        e.get(key)
            .filter(|c| {
                c.content == content && (0..Self::REUSE_SECS).contains(&(now - c.issued_at))
            })
            .map(|c| c.signed.clone())
    }

    pub fn put(&self, key: &str, content: Vec<u8>, issued_at: i64, signed: Vec<u8>) {
        let mut e = self.entries.lock().expect("record cache lock");
        if e.len() > 10_000 {
            e.clear();
        }
        e.insert(
            key.to_owned(),
            CachedRecord {
                content,
                issued_at,
                signed,
            },
        );
    }
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
