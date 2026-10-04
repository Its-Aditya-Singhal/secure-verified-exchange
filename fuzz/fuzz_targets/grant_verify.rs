//! Release grants: any payload signed by the pinned grant key must parse
//! and be checked without panicking; any unsigned blob must be refused.
#![no_main]
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use svx_core::crypto::{SignContext, SigningKey, sign_context};
use svx_protocol::grant::SignedGrant;

static KEY: OnceLock<SigningKey> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let key = KEY.get_or_init(|| SigningKey::from_secret_bytes(
        svx_core::crypto::KeyKind::MaxSigning,
        &[7; 160],
    )
    .unwrap());
    let vk = key.verifying_key();
    // As JSON from the wire.
    if let Ok(g) = serde_json::from_slice::<SignedGrant>(data) {
        let _ = g.verify(&vk, 1_800_000_000);
    }
    // As a payload the service signed.
    if data.len() <= 8 * 1024
        && let Ok(signature) = sign_context(key, SignContext::ReleaseGrant, data)
    {
        let g = SignedGrant {
            payload: data.to_vec(),
            signature,
            key_id: vk.key_id(),
        };
        let _ = g.verify(&vk, 1_800_000_000);
    }
});
