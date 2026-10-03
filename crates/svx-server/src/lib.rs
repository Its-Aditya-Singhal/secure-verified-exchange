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
pub mod policy;
mod routes;

use std::sync::Arc;

use axum::Router;
use svx_core::format::Identifier;
use svx_oidc::Validator;

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
    /// Allows plain-http loopback IdPs and key agents. Never in production.
    pub dev: bool,
}

/// Apply migrations and build the router.
pub async fn app(state: AppState) -> anyhow::Result<Router> {
    sqlx::migrate!("./migrations").run(&state.db).await?;
    Ok(router(state))
}
