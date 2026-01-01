//! Rust runtime side of the Plan-05 correspondence audit.
//!
//! Parses an `strace -f` capture into the same `Effect` grammar as the
//! Lean model (`proof/Seck/Effects.lean`) and runs `check_trace`, the
//! Rust analog of `Trace.checkIOBoundary` (`proof/Seck/Checker.lean`).
//!
//! Whereas the Lean proof shows that *no well-typed host/reader program
//! can violate the IO boundary in principle*, this harness shows that
//! *the actual running binary did not violate it on this run*. The two
//! together rule out implementation bugs that fall outside the Lean
//! model's coverage.

pub mod checker;
pub mod strace_parse;

pub use checker::{InvariantError, check_trace};
pub use strace_parse::{Effect, parse_strace};
