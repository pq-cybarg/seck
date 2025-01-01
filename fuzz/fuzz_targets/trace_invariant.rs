#![no_main]
//! Fuzz target for the strace parser + checker. Random input must not
//! crash; the checker may return Ok or Err but never panic.

use libfuzzer_sys::fuzz_target;
use seck_trace_check::{check_trace, parse_strace};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let effs = parse_strace(s);
        let _ = check_trace(&effs, b"CANARY");
    }
});
