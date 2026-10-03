//! High-level SVX operations.
//!
//! * [`pack`] — encrypt, seal key shares, sign and write a `.svx` container
//!   in a single streaming pass with bounded memory.
//! * [`verify`] — check structure, sender trust, payload commitment and
//!   signature without any decryption keys.
//! * [`VerifiedArtifact::decrypt`] — given both released key shares,
//!   authenticate and decrypt the payload.
//!
//! In Managed Mode the two key shares are released by the managed service
//! and the recipient organization's key agent only after authentication and
//! authorization. This crate never decides *whether* a user may open an
//! artifact; it only enforces that nothing is decrypted unless the container
//! verifies and the released shares are the right ones.

#![forbid(unsafe_code)]

mod error;
pub mod keyfile;
mod manifest;
mod pack;
mod trust;
mod verify;

pub use error::{CoreError, Result};
pub use manifest::{FileEntry, MANIFEST_VERSION, Manifest};
pub use pack::{PackRequest, PackSummary, pack};
pub use trust::TrustStore;
pub use verify::{VerifiedArtifact, VerifiedHead, inspect, unwrap_envelope, verify, verify_head};

pub use svx_crypto as crypto;
pub use svx_format as format;
