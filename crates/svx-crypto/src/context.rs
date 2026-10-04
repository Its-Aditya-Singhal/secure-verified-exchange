//! Domain-separated signatures for non-artifact objects (release grants,
//! registry records, the service record, account requests). A signature
//! made for one context can never verify in another, or as an artifact
//! signature.
//!
//! Only post-quantum keys sign or verify here: hybrid Ed25519 + ML-DSA-65
//! (protocol v3) or Max keys (suite SVX-2, protocol v4). With a Max key,
//! long-lived objects (registry and service records) carry all three
//! signatures; short-lived ones (grants, account requests, checked within
//! minutes) carry Ed25519 + ML-DSA-87. Every part present must verify; a
//! classical Ed25519 key or signature is refused.

use crate::error::{CryptoError, Result};
use crate::keys::{KeyKind, SigSet, SigningKey, VerifyingKey};

/// What a context signature is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignContext {
    /// A short-lived key-release grant issued by the managed service.
    ReleaseGrant,
    /// An organization record published by the registry.
    RegistryRecord,
    /// The managed service's own public keys, published by the registry.
    ServiceRecord,
    /// A request from a personal account's device, signed with its key.
    AccountRequest,
    /// A desktop app release (versions, download hashes), signed offline
    /// with the release key the app pins.
    ReleaseManifest,
}

impl SignContext {
    fn label(self) -> &'static [u8] {
        match self {
            SignContext::ReleaseGrant => b"SVX-1 grant\0",
            SignContext::RegistryRecord => b"SVX-1 registry\0",
            SignContext::ServiceRecord => b"SVX-1 service\0",
            SignContext::AccountRequest => b"SVX-1 account request\0",
            SignContext::ReleaseManifest => b"SVX-1 release manifest\0",
        }
    }

    /// Which parts of a Max key sign in this context.
    fn set(self) -> SigSet {
        match self {
            SignContext::RegistryRecord
            | SignContext::ServiceRecord
            | SignContext::ReleaseManifest => SigSet::Full,
            SignContext::ReleaseGrant | SignContext::AccountRequest => SigSet::Fast,
        }
    }
}

fn message(ctx: SignContext, key: KeyKind, msg: &[u8]) -> Vec<u8> {
    // Max keys sign under a distinct prefix, so a v3 (hybrid) signature and
    // a v4 one are never interchangeable.
    let mut m = if key == KeyKind::MaxSigning {
        b"SVX-2 ".to_vec()
    } else {
        Vec::new()
    };
    m.extend_from_slice(ctx.label());
    m.extend_from_slice(msg);
    m
}

fn allowed(kind: KeyKind) -> bool {
    matches!(kind, KeyKind::HybridSigning | KeyKind::MaxSigning)
}

/// Sign `msg` under `ctx` with a post-quantum key (ML-DSA and SLH-DSA hedged
/// with the OS RNG).
pub fn sign_context(key: &SigningKey, ctx: SignContext, msg: &[u8]) -> Result<Vec<u8>> {
    if !allowed(key.kind()) {
        return Err(CryptoError::WrongKeyKind);
    }
    key.sign_raw(
        &message(ctx, key.kind(), msg),
        ctx.set(),
        &mut crate::os_rng(),
    )
}

/// Verify a context signature: post-quantum key only, every part must verify.
pub fn verify_context(key: &VerifyingKey, ctx: SignContext, msg: &[u8], sig: &[u8]) -> Result<()> {
    if !allowed(key.kind()) {
        return Err(CryptoError::BadSignature);
    }
    key.verify_raw(&message(ctx, key.kind(), msg), sig, ctx.set())
}
