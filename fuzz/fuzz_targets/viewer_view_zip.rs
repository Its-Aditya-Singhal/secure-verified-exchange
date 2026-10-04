//! Reading a view-only container in memory: only the two allowed entry
//! shapes, and what is accepted must build and read back identically.
#![no_main]
use libfuzzer_sys::fuzz_target;
use svx_client::viewfile::{build, parse};

fuzz_target!(|data: &[u8]| {
    if let Ok(parts) = parse(data) {
        assert!(parts.display_name.starts_with("display."));
        let again = parse(&build(&parts).expect("accepted parts must build")).unwrap();
        assert_eq!(again, parts);
    }
});
