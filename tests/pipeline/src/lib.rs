//! Scripted mock backend for pipeline integration tests. Returns the
//! pre-recorded `script` strings in order, ignoring the prompt.

use seck_plugin::{BackendError, InferenceConfig, LlmBackend};
use std::sync::Mutex;

pub struct ScriptedBackend {
    pub script: Vec<String>,
    pub idx: Mutex<usize>,
}

impl ScriptedBackend {
    pub fn new(script: Vec<String>) -> Self {
        Self {
            script,
            idx: Mutex::new(0),
        }
    }
}

impl LlmBackend for ScriptedBackend {
    fn name(&self) -> &'static str {
        "scripted"
    }
    fn load(&mut self, _cfg: &InferenceConfig) -> Result<(), BackendError> {
        Ok(())
    }
    fn generate(&mut self, _prompt: &str) -> Result<String, BackendError> {
        let mut g = self.idx.lock().unwrap();
        let i = *g;
        *g += 1;
        Ok(self.script.get(i).cloned().unwrap_or_default())
    }
}
