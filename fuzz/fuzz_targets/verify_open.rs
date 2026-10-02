//! Full verification and (if verification somehow passes) decryption with
//! the published test keys. Seed with test-vectors/v1/*.svx.
#![no_main]
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use svx_core::TrustStore;
use svx_core::format::EnvelopeRole;
use svx_testvectors::TestKeys;

static KEYS: OnceLock<(TestKeys, TrustStore)> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let (keys, trust) = KEYS.get_or_init(|| {
        let k = TestKeys::new();
        let t = k.trust();
        (k, t)
    });
    let Ok(v) = svx_core::verify(data, trust) else { return };
    let (Ok(s), Ok(r)) = (
        v.unwrap_share(EnvelopeRole::Service, &keys.service_kem),
        v.unwrap_share(EnvelopeRole::RecipientOrg, &keys.example_kem),
    ) else {
        return;
    };
    let _ = v.decrypt(data, &s, &r, std::io::sink());
});
