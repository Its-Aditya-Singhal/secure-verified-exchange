//! Desktop app release manifests: parsing, verification with the pinned
//! release key, and the checks applied after the signature.
#![no_main]
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use svx_core::crypto::{KeyKind, SigningKey};
use svx_protocol::update::{
    ReleaseManifest, SignedReleaseManifest, parse_version, release_key_fingerprint,
};

static FP: OnceLock<String> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let fp = FP.get_or_init(|| {
        release_key_fingerprint(
            &SigningKey::from_secret_bytes(KeyKind::MaxSigning, &[5; 160])
                .unwrap()
                .verifying_key(),
        )
    });
    if let Ok(s) = serde_json::from_slice::<SignedReleaseManifest>(data) {
        let _ = s.verify(fp);
    }
    if let Ok(m) = serde_json::from_slice::<ReleaseManifest>(data) {
        let _ = m.check();
        let _ = parse_version(&m.version);
    }
    if let Ok(t) = std::str::from_utf8(data) {
        let _ = parse_version(t);
    }
});
