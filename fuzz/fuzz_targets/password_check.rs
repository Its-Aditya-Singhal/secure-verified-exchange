//! The password rules the service runs on every sign-up and password
//! change: they must never panic or take long, whatever the input.
#![no_main]
use libfuzzer_sys::fuzz_target;
use svx_protocol::email_account::{password_strength, valid_code, valid_name};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let (pw, rest) = text.split_once('\n').unwrap_or((text, ""));
    let inputs: Vec<&str> = rest.split('\n').take(3).collect();
    let s = password_strength(pw, &inputs);
    assert!(s.score <= 4);
    if s.ok {
        assert!(pw.chars().count() >= 12);
    }
    let _ = valid_name(pw);
    let _ = valid_code(pw);
});
