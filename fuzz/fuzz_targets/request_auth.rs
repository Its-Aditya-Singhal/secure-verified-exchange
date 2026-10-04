//! Signed device requests: header parsing and verification.
#![no_main]
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use svx_core::crypto::{KeyKind, SigningKey, VerifyingKey};
use svx_protocol::personal::{
    HDR_ACCOUNT, HDR_KEY_ID, HDR_NONCE, HDR_SIGNATURE, HDR_TIME, RequestAuth,
};

static KEY: OnceLock<VerifyingKey> = OnceLock::new();

const NAMES: [&str; 5] = [HDR_ACCOUNT, HDR_KEY_ID, HDR_TIME, HDR_NONCE, HDR_SIGNATURE];

fuzz_target!(|data: &[u8]| {
    let vk = KEY.get_or_init(|| {
        SigningKey::from_secret_bytes(KeyKind::MaxSigning, &[3; 160])
            .unwrap()
            .verifying_key()
    });
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // Five header values, separated by newlines, then the body.
    let mut parts = text.splitn(6, '\n');
    let values: Vec<&str> = (0..5).map(|_| parts.next().unwrap_or("")).collect();
    let body = parts.next().unwrap_or("");
    let get = |n: &str| {
        NAMES
            .iter()
            .position(|k| k.eq_ignore_ascii_case(n))
            .map(|i| values[i])
    };
    if let Some(auth) = RequestAuth::from_headers(get) {
        let _ = auth.verify(vk, "POST", "/v1/me/files", body.as_bytes(), 1_800_000_000);
    }
});
