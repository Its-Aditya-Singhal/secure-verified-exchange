//! Registry and service records from the wire: parsing, verification with
//! the pinned key, and using a record's keys.
#![no_main]
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use svx_core::TrustStore;
use svx_core::crypto::{KeyKind, SigningKey, VerifyingKey};
use svx_protocol::{OrgRecord, ServiceRecord, SignedOrgRecord, SignedServiceRecord};

static KEY: OnceLock<VerifyingKey> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let vk = KEY.get_or_init(|| {
        SigningKey::from_secret_bytes(KeyKind::MaxSigning, &[9; 160])
            .unwrap()
            .verifying_key()
    });
    if let Ok(s) = serde_json::from_slice::<SignedOrgRecord>(data) {
        let _ = s.verify(vk, "example-corp", 1_800_000_000);
        let _ = s.verify_for_email(vk, "bob@example.test", 1_800_000_000);
    }
    if let Ok(s) = serde_json::from_slice::<SignedServiceRecord>(data) {
        let _ = s.verify(vk, 1_800_000_000);
    }
    // What a verified record's users do with it.
    if let Ok(r) = serde_json::from_slice::<OrgRecord>(data) {
        let _ = r.active_kem_key().map(|k| k.kem_public_key());
        let _ = r.add_signing_keys_to(&mut TrustStore::new());
    }
    let _ = serde_json::from_slice::<ServiceRecord>(data);
});
