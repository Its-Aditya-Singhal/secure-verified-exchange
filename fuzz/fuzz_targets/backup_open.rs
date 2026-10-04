//! Backup files (`*.svxbackup`): parsing and the password check. Files
//! asking for more than 64 KiB of Argon2 memory are skipped (real backups
//! use 256 MiB; the parser's bounds are tested separately).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() >= 12 {
        let m = u32::from_le_bytes(data[8..12].try_into().unwrap());
        if m > 64 {
            return;
        }
    }
    let _ = svx_core::crypto::open_with_password("correct horse battery staple", data);
});
