//! In-sandbox reader library. Plan 01 ships the protocol parser and
//! nonce-delimited prompt assembler. The actual main loop (Task 15) needs
//! the Linux sandbox + llama.cpp backend; on macOS Plan 02 adds Seatbelt.

pub mod prompt;
pub mod protocol;
