//! Domain-separated hybrid signatures for non-artifact objects (release
//! grants, registry records, the service record). A signature made for one
//! context can never verify in another, or as an artifact signature.
//!
//! Only hybrid Ed25519 + ML-DSA-65 keys sign or verify here, and both halves
//! must verify: a classical Ed25519 key or signature is refused.

use crate::error::{CryptoError, Result};
use crate::keys::{KeyKind, SigningKey, VerifyingKey};

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
}

impl SignContext {
    fn label(self) -> &'static [u8] {
        match self {
            SignContext::ReleaseGrant => b"SVX-1 grant\0",
            SignContext::RegistryRecord => b"SVX-1 registry\0",
            SignContext::ServiceRecord => b"SVX-1 service\0",
            SignContext::AccountRequest => b"SVX-1 account request\0",
        }
    }
}

fn message(ctx: SignContext, msg: &[u8]) -> Vec<u8> {
    let mut m = ctx.label().to_vec();
    m.extend_from_slice(msg);
    m
}

/// Sign `msg` under `ctx` with a hybrid key (`Ed25519 sig ‖ ML-DSA-65 sig`,
/// the ML-DSA half hedged with the OS RNG).
pub fn sign_context(key: &SigningKey, ctx: SignContext, msg: &[u8]) -> Result<Vec<u8>> {
    if key.kind() != KeyKind::HybridSigning {
        return Err(CryptoError::WrongKeyKind);
    }
    key.sign_raw(&message(ctx, msg), &mut crate::os_rng())
}

/// Verify a context signature: hybrid key only, both halves must verify.
pub fn verify_context(key: &VerifyingKey, ctx: SignContext, msg: &[u8], sig: &[u8]) -> Result<()> {
    if key.kind() != KeyKind::HybridSigning {
        return Err(CryptoError::BadSignature);
    }
    key.verify_raw(&message(ctx, msg), sig)
}
