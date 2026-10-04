//! Opening a folder: hardened zip extraction (names, types, sizes, ratio)
//! into a fresh directory. Nothing may be written outside it, and a failed
//! extraction leaves nothing behind.
#![no_main]
use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use svx_client::folder::{Limits, extract};

fuzz_target!(|data: &[u8]| {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("out");
    let limits = Limits {
        max_entries: 64,
        max_total_bytes: 1 << 20,
        ..Limits::default()
    };
    match extract(Cursor::new(data), data.len() as u64, &dest, limits) {
        Ok(()) => assert!(dest.is_dir()),
        Err(_) => assert!(!dest.exists(), "a failed extraction left files behind"),
    }
    // Only `out` may exist in the parent.
    let names: Vec<_> = std::fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(names.len() <= 1, "wrote outside the destination: {names:?}");
});
