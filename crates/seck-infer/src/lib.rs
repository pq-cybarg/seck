//! LLM backends. The stub returns canned JSON for tests; real backends
//! are feature-gated to keep the build light.

pub mod stub;

#[cfg(feature = "llama-cpp")]
pub mod llama_cpp;

pub mod ollama; // built unconditionally — pure stdlib + serde

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub mod mlx;
