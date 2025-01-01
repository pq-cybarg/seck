//! Deterministic stub backend. Returns a canned JSON-shaped finding so the
//! pipeline can run end-to-end without an actual LLM. Real llama.cpp +
//! Ollama + MLX backends arrive in Plan 08; until then this is what
//! `--backend=stub` (or `llama-cpp` while the feature is off) returns.

use seck_plugin::{BackendError, InferenceConfig, LlmBackend};

pub struct StubBackend {
    cfg: Option<InferenceConfig>,
}

impl Default for StubBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl StubBackend {
    pub fn new() -> Self {
        Self { cfg: None }
    }
}

impl LlmBackend for StubBackend {
    fn name(&self) -> &'static str {
        "stub"
    }

    fn load(&mut self, cfg: &InferenceConfig) -> Result<(), BackendError> {
        self.cfg = Some(cfg.clone());
        Ok(())
    }

    fn generate(&mut self, _prompt: &str) -> Result<String, BackendError> {
        let _ = self
            .cfg
            .as_ref()
            .ok_or_else(|| BackendError::Generation("not loaded".into()))?;
        Ok(r#"{"findings":[{"summary":"stub backend: no actual analysis was performed. The pipeline ran end-to-end and would emit real findings if a real LLM backend were configured.","files":["(all)"],"category":"note","confidence":"low","evidence_quote":""}]}"#.into())
    }
}
