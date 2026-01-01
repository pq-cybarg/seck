//! llama.cpp backend. Compiled only when `--features llama-cpp` is set.
//!
//! The full FFI binding to `libllama.so` is intentionally out of scope
//! for the workspace build: a wholesale link to llama.cpp at workspace
//! level pulls in a C++ toolchain dependency and ~50MB of code we don't
//! need for ordinary `cargo test --workspace`. The wiring under this
//! feature gate is a small surface that the executor's build can
//! replace with a real FFI shim.
#![cfg(feature = "llama-cpp")]

use crate::stub::StubBackend;
use seck_plugin::{InferenceConfig, LlmBackend};

/// Placeholder llama.cpp backend. Delegates to the stub so the API
/// surface compiles end-to-end under `--features llama-cpp`. The real
/// FFI implementation lives in a follow-up shipped by the release
/// build (which links libllama statically).
pub struct LlamaCppBackend(StubBackend);

impl LlamaCppBackend {
    pub fn new() -> Self {
        Self(StubBackend::new())
    }
}

impl Default for LlamaCppBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl LlmBackend for LlamaCppBackend {
    fn name(&self) -> &'static str {
        "llama-cpp-placeholder"
    }

    fn load(&mut self, cfg: &InferenceConfig) -> anyhow::Result<()> {
        self.0.load(cfg)
    }

    fn generate(&mut self, prompt: &str) -> anyhow::Result<String> {
        self.0.generate(prompt)
    }
}
