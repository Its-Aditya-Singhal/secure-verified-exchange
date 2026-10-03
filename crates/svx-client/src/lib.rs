//! The SVX client library.
//!
//! Everything an end user or administrator does with SVX, independent of any
//! user interface: the `svx` CLI is a thin layer over this crate, and the
//! language SDKs (Phase 4) wrap it too.
//!
//! * [`config`] — which managed service to use and the pinned registry key.
//! * [`login`] — OIDC login: browser (RFC 8252 loopback) or dev.
//! * [`session`] — the short-lived admin session cache.
//! * [`registry`] — verified organization and service records.
//! * [`open()`] — the fail-closed open flow.
//! * [`pack`] — managed packing (recipient keys from the registry).
//! * [`admin`] — revocation, policies, audit.

#![forbid(unsafe_code)]

pub mod admin;
pub mod config;
mod error;
pub mod login;
mod open;
pub mod pack;
pub mod registry;
pub mod session;

pub use config::ClientConfig;
pub use error::{ClientError, Result};
pub use login::{Authenticator, BrowserLogin, DevLogin};
pub use open::{OpenOutcome, Output, Step, open};

/// Seconds since the Unix epoch, UTC.
pub fn now() -> i64 {
    svx_protocol::unix_now()
}
