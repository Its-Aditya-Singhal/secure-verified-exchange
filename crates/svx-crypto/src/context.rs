//! Domain-separated Ed25519 signatures for non-artifact objects (release
//! grants, registry records). A signature made for one context can never
//! verify in another, or as an artifact signature.

use crate::error::{CryptoError, Result};
use crate::keys::{SigningKey, VerifyingKey};

/// What a context signature is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignContext {
    /// A short-lived key-release grant issued by the managed service.
    ReleaseGrant,
    /// An organization record published by the registry.
    RegistryRecord,
}

impl SignContext {
    fn label(self) -> &'static [u8] {
        match self {
            SignContext::ReleaseGrant => b"SVX-1 grant\0",
            SignContext::RegistryRecord => b"SVX-1 registry\0",
        }
    }
}

fn message(ctx: SignContext, msg: &[u8]) -> Vec<u8> {
    let mut m = ctx.label().to_vec();
    m.extend_from_slice(msg);
    m
}

/// Sign `msg` under `ctx`.
pub fn sign_context(key: &SigningKey, ctx: SignContext, msg: &[u8]) -> [u8; 64] {
    key.sign_raw(&message(ctx, msg))
}

/// Verify a context signature (strict Ed25519).
pub fn verify_context(key: &VerifyingKey, ctx: SignContext, msg: &[u8], sig: &[u8]) -> Result<()> {
    if sig.len() != 64 {
        return Err(CryptoError::BadSignature);
    }
    key.verify_raw(&message(ctx, msg), sig)
}
