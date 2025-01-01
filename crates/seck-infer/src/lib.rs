//! LLM backends. Plan 01 ships a deterministic STUB backend that returns
//! a canned JSON report; the real llama.cpp wiring is deferred to a Linux
//! session in Plan 01 follow-up + Plan 08 (Ollama/MLX).
//!
//! The stub demonstrates the full data-flow architecture end-to-end and
//! lets the integration tests run without the heavy llama-cpp-2 C
//! dependency. Selecting `--backend=llama-cpp` returns the stub for now;
//! a follow-up patch enables the real backend behind a `llama-cpp` feature.

pub mod stub;

#[cfg(feature = "llama-cpp")]
pub mod llama_cpp;
