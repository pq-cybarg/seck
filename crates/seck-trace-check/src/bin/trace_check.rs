//! CLI entry point used by the `trace-vs-model` CI workflow.
//!
//! Usage:
//!
//!   seck-trace-check <strace-output-file> <canary>
//!
//! Exits 0 if the trace satisfies the IO boundary invariant for the
//! given canary string; non-zero with a diagnostic on stderr otherwise.

use anyhow::Context;
use seck_trace_check::{check_trace, parse_strace};

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let trace_path = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing arg: trace-output-file"))?;
    let canary = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing arg: canary"))?;
    let body = std::fs::read_to_string(&trace_path)
        .with_context(|| format!("read {trace_path}"))?;
    let effs = parse_strace(&body);
    match check_trace(&effs, canary.as_bytes()) {
        Ok(()) => {
            println!("trace-check: IO boundary holds ({} effects scanned)", effs.len());
            Ok(())
        }
        Err(e) => {
            eprintln!("trace-check FAILED: {e}");
            std::process::exit(2);
        }
    }
}
