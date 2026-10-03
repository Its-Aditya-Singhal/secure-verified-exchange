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
    /// The managed service's own public keys, published by the registry.
    ServiceRecord,
}

impl SignContext {
    fn label(self) -> &'static [u8] {
        match self {
            SignContext::ReleaseGrant => b"SVX-1 grant\0",
            SignContext::RegistryRecord => b"SVX-1 registry\0",
            SignContext::ServiceRecord => b"SVX-1 service\0",
        }
    }
}

fn message(ctx: SignContext, msg: &[u8]) -> Vec<u8> {
    let mut m = ctx.label().to_vec();
    m.extend_from_slice(msg);
    m
}

/// Sign `msg` under `ctx` with an Ed25519 key (registry and service keys
/// are Ed25519; a hybrid key here is a programming error).
pub fn sign_context(key: &SigningKey, ctx: SignContext, msg: &[u8]) -> [u8; 64] {
    use ed25519_dalek::Signer;
    match key {
        SigningKey::Ed25519(k) => k.sign(&message(ctx, msg)).to_bytes(),
        SigningKey::Hybrid(_) => panic!("context signatures use Ed25519 keys"),
    }
}

/// Verify a context signature (strict Ed25519).
pub fn verify_context(key: &VerifyingKey, ctx: SignContext, msg: &[u8], sig: &[u8]) -> Result<()> {
    if sig.len() != 64 || key.kind() != crate::KeyKind::Ed25519Signing {
        return Err(CryptoError::BadSignature);
    }
    key.verify_raw(&message(ctx, msg), sig)
}
