//! LLM backends. The stub returns canned JSON for tests; real backends
//! are feature-gated to keep the build light.

pub mod stub;

#[cfg(feature = "llama-cpp")]
pub mod llama_cpp;

// Ollama talks to a pre-opened Unix-domain socket, so it's Unix-only.
// On Windows the `seck mcp ollama` integration is replaced by a
// named-pipe variant in a follow-up; for now we cfg it out.
#[cfg(unix)]
pub mod ollama;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub mod mlx;
