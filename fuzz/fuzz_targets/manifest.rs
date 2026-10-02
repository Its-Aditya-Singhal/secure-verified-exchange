//! Decrypted manifests come from an authenticated sender, but must still
//! never panic or yield an unsafe file name.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = svx_core::Manifest::from_bytes(data) {
        for f in &m.files {
            assert!(!f.name.contains('/') && !f.name.contains('\\') && f.name != "..");
        }
    }
});
