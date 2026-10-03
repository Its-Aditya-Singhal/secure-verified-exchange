//! The SVX client library.
//!
//! Everything an end user or administrator does with SVX, independent of any
//! user interface: the `svx` CLI is a thin layer over this crate, and the
//! language SDKs (`svx-py`, `svx-node`) bind [`Client`].
//!
//! * [`config`] — which managed service to use and the pinned registry key.
//! * [`login`] — OIDC login: browser (RFC 8252 loopback) or dev.
//! * [`session`] — the short-lived admin session cache.
//! * [`registry`] — verified organization and service records.
//! * [`open()`] — the fail-closed open flow.
//! * [`pack`] — managed packing (recipient keys from the registry).
//! * [`admin`] — revocation, policies, audit.
//! * [`account`] — login method, admin session, `whoami`.
//! * [`info`] — inspect, verify and status without key release.
//! * [`keys`] — key file generation.
//! * [`setup`] — first-run setup verified against the pinned registry key.

#![forbid(unsafe_code)]

pub mod account;
pub mod admin;
mod client;
pub mod config;
mod error;
pub mod info;
pub mod keys;
pub mod login;
mod open;
pub mod pack;
pub mod registry;
pub mod session;
pub mod setup;

pub use client::{Client, PackOptions, PackResult};
pub use config::ClientConfig;
pub use error::{ClientError, ErrorKind, Result};
pub use info::{ArtifactInfo, Status, artifact_id_of, status};
pub use login::{Authenticator, BrowserLogin, DevLogin};
pub use open::{OpenOutcome, Output, Step, open, output_path};

/// Seconds since the Unix epoch, UTC.
pub fn now() -> i64 {
    svx_protocol::unix_now()
}
