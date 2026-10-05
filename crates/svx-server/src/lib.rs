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

pub mod admin_ops;
pub mod audit;
pub mod db;
pub mod dns;
pub mod error;
pub mod keys;
pub mod limits;
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
    /// Abuse limits (see [`limits`]).
    pub limits: limits::Limits,
    /// Header carrying the client's address, set by a trusted proxy
    /// (`--client-ip-header`). Without it the connection's address is used.
    pub client_ip_header: Option<axum::http::HeaderName>,
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
    /// key -> (window length, window number, calls in it)
    windows: Mutex<HashMap<String, (i64, i64, u32)>>,
}

impl RateLimiter {
    /// Whether `key` may make another call this minute (at most `per_minute`).
    pub fn allow(&self, key: &str, per_minute: u32) -> bool {
        self.allow_in(key, per_minute, 60)
    }

    /// Whether `key` may make another call in the current window of
    /// `window_secs` seconds (at most `limit` per window).
    pub fn allow_in(&self, key: &str, limit: u32, window_secs: i64) -> bool {
        self.allow_at(key, limit, window_secs, svx_protocol::unix_now())
    }

    fn allow_at(&self, key: &str, limit: u32, window_secs: i64, now: i64) -> bool {
        let window_secs = window_secs.max(1);
        let n = now.div_euclid(window_secs);
        let mut w = self.windows.lock().expect("rate limiter lock");
        if w.len() > 100_000 {
            w.retain(|_, (len, num, _)| *num == now.div_euclid(*len));
        }
        let e = w.entry(key.to_owned()).or_insert((window_secs, n, 0));
        if e.0 != window_secs || e.1 != n {
            *e = (window_secs, n, 0);
        }
        e.2 = e.2.saturating_add(1);
        e.2 <= limit
    }
}

/// Apply migrations and build the router.
pub async fn app(state: AppState) -> anyhow::Result<Router> {
    sqlx::migrate!("./migrations").run(&state.db).await?;
    Ok(router(state))
}

#[cfg(test)]
mod limiter_tests {
    use super::RateLimiter;

    #[test]
    fn windows_reset_and_keys_are_separate() {
        let l = RateLimiter::default();
        let t = 1_000_000 * 3600;
        assert!(l.allow_at("a", 2, 3600, t));
        assert!(l.allow_at("a", 2, 3600, t + 10));
        assert!(!l.allow_at("a", 2, 3600, t + 20));
        assert!(l.allow_at("b", 2, 3600, t + 20));
        assert!(l.allow_at("a", 2, 3600, t + 3600));
    }
}
