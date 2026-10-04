//! Key files (`*.sign.key`, `*.kem.pub`, …) as untrusted input.
#![no_main]
use libfuzzer_sys::fuzz_target;
use svx_core::keyfile;

fuzz_target!(|data: &[u8]| {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), data).unwrap();
    let p = tmp.path();
    let _ = keyfile::load_signing_key(p);
    let _ = keyfile::load_verifying_key(p);
    let _ = keyfile::load_kem_secret(p);
    let _ = keyfile::load_kem_public(p);
});
