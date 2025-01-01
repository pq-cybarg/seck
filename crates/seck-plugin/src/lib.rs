//! Plugin traits for backends. Implementations live in `seck-infer`,
//! `seck-sandbox`, etc.

use seck_taint::Untainted;
use std::path::PathBuf;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InferenceConfig {
    pub model_path: PathBuf,
    pub temperature: f32,
    pub seed: u64,
    pub max_tokens: u32,
    pub context_window: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("model load failed: {0}")]
    ModelLoad(String),
    #[error("generation failed: {0}")]
    Generation(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// LLM backend trait. Implementations run *inside* the sandbox. The caller
/// has already nonce-delimited any tainted payload inside `prompt`. The
/// caller is responsible for treating the returned string as tainted output.
pub trait LlmBackend: Send + Sync {
    fn name(&self) -> &'static str;
    fn load(&mut self, cfg: &InferenceConfig) -> Result<(), BackendError>;
    fn generate(&mut self, prompt: &str) -> Result<String, BackendError>;
}

/// Sandbox backend trait. Each implementation knows how to spawn the
/// reader child with the platform's strongest sandbox.
pub trait SandboxBackend {
    fn name(&self) -> &'static str;
    /// SHA3-256 of the platform's audited profile/ruleset/filter. Used for
    /// the attestation block in the report.
    fn profile_sha3_256(&self) -> [u8; 32];
}

/// Marker: the plugin host has confirmed the plugin originated from the
/// trusted bundle. Plugins not carrying this proof are refused.
pub struct TrustedPlugin<T> {
    pub plugin: T,
    pub manifest_attestation: Untainted<[u8; 32]>,
}
