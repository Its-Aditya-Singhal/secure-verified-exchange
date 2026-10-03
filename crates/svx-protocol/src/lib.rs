//! SVX Managed Mode protocol (see `docs/architecture.md` §6 and `docs/api.md`).
//!
//! * [`types`] — JSON request/response bodies for the managed service and
//!   the recipient key agent.
//! * [`grant`] — the short-lived, signed release grant the service hands to
//!   the client for the key agent.
//! * [`registry`] — signed organization records.
//! * [`policy`] — authorization policy documents.
//! * [`client`] — the release client used by `svx` and the test harness.
//! * [`oidc_login`] — OIDC authorization-code + PKCE helpers.
//! * [`personal`] — personal accounts, signed requests, file rules and
//!   sender approval.

#![forbid(unsafe_code)]

pub mod admin;
pub mod client;
pub mod encoding;
pub mod grant;
pub mod oidc_login;
pub mod personal;
pub mod policy;
pub mod registry;
pub mod types;

pub use client::{ManagedClient, ProtocolError, ReleaseSession, check_url};
pub use grant::{Grant, SignedGrant};
pub use policy::Policy;
pub use registry::{
    KeyEntry, KeyKindWire, KeyStatus, OrgRecord, ServiceInfo, ServiceRecord, SignedOrgRecord,
    SignedServiceRecord,
};
/// HTTP method of a signed request ([`ManagedClient::signed`]).
pub use reqwest::Method;
pub use types::*;

/// Current wire protocol version, included in grants and records. Version 2
/// carries post-quantum hybrid keys (X-Wing, Ed25519 + ML-DSA-65); version 3
/// signs grants and registry and service records with hybrid keys too.
pub const PROTOCOL_VERSION: u32 = 3;

/// Seconds since the Unix epoch, UTC.
pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
