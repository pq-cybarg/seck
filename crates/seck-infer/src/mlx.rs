//! MLX backend — Apple Silicon native. Spawns a sibling Swift runner
//! binary (`MLXRunner`) that links against the MLX framework, owns the
//! model weights, and communicates with us over pipes.
//!
//! Protocol (line-oriented, on the runner's stdin/stdout):
//!   PROMPT\n
//!   <prompt text spanning N lines>\n
//!   END\n
//!   ... runner emits ...
//!   RESPONSE\n
//!   <output text spanning N lines>\n
//!   END\n
//!
//! The Swift runner is built separately (see
//! `platform/macos/mlx-runner/`). On non-macOS or non-aarch64 platforms,
//! `load()` returns an error immediately.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use seck_plugin::{BackendError, InferenceConfig, LlmBackend};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};

pub struct MlxBackend {
    child: Option<Child>,
    cfg: Option<InferenceConfig>,
}

impl Default for MlxBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MlxBackend {
    pub fn new() -> Self {
        Self {
            child: None,
            cfg: None,
        }
    }
}

impl LlmBackend for MlxBackend {
    fn name(&self) -> &'static str {
        "mlx"
    }

    fn load(&mut self, cfg: &InferenceConfig) -> Result<(), BackendError> {
        // Locate MLXRunner next to the current binary.
        let runner = std::env::current_exe()
            .map_err(BackendError::Io)?
            .parent()
            .ok_or_else(|| BackendError::ModelLoad("no parent dir for current_exe".into()))?
            .join("MLXRunner");
        let child = Command::new(&runner)
            .env("SECK_MLX_MODEL", &cfg.model_path)
            .env("SECK_MLX_SEED", cfg.seed.to_string())
            .env("SECK_MLX_MAX_TOKENS", cfg.max_tokens.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| BackendError::ModelLoad(format!("spawn {runner:?}: {e}")))?;
        self.child = Some(child);
        self.cfg = Some(cfg.clone());
        Ok(())
    }

    fn generate(&mut self, prompt: &str) -> Result<String, BackendError> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| BackendError::Generation("not loaded".into()))?;
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| BackendError::Generation("no stdin to MLXRunner".into()))?;
        writeln!(stdin, "PROMPT").map_err(BackendError::Io)?;
        write!(stdin, "{prompt}").map_err(BackendError::Io)?;
        writeln!(stdin, "\nEND").map_err(BackendError::Io)?;
        let stdout = child
            .stdout
            .as_mut()
            .ok_or_else(|| BackendError::Generation("no stdout from MLXRunner".into()))?;
        let reader = BufReader::new(stdout);
        let mut acc = String::new();
        let mut in_response = false;
        for line in reader.lines() {
            let l = line.map_err(BackendError::Io)?;
            if !in_response {
                if l == "RESPONSE" {
                    in_response = true;
                }
                continue;
            }
            if l == "END" {
                break;
            }
            acc.push_str(&l);
            acc.push('\n');
        }
        Ok(acc.trim_end_matches('\n').to_string())
    }
}
