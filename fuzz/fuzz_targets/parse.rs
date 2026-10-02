//! The container parser must never panic, hang or over-allocate on any input.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = svx_core::format::parse(data);
    let _ = svx_core::inspect(data);
});
