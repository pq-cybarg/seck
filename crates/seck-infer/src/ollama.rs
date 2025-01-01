//! Ollama backend — strictly UDS-only. Refuses any TCP / HTTPS host.
//!
//! The orchestrator is expected to start `ollama serve` in a sibling
//! sandbox with `OLLAMA_HOST=unix:///<path>` so the network namespace
//! stays empty. We connect to that UDS, speak HTTP/1.1 by hand
//! (no reqwest — that pulls in a TLS stack we don't need for a
//! Unix-domain socket), and parse the JSON response.

use seck_plugin::{BackendError, InferenceConfig, LlmBackend};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

pub struct OllamaBackend {
    uds: PathBuf,
    cfg: Option<InferenceConfig>,
}

impl OllamaBackend {
    /// Construct from a `unix://<path>` URI. Returns an error for any
    /// scheme other than `unix://`.
    pub fn new(host: &str) -> Result<Self, BackendError> {
        let uds = host.strip_prefix("unix://").ok_or_else(|| {
            BackendError::ModelLoad(format!(
                "Ollama backend accepts only unix://<path>; got {host}"
            ))
        })?;
        Ok(Self {
            uds: PathBuf::from(uds),
            cfg: None,
        })
    }
}

impl LlmBackend for OllamaBackend {
    fn name(&self) -> &'static str {
        "ollama"
    }

    fn load(&mut self, cfg: &InferenceConfig) -> Result<(), BackendError> {
        self.cfg = Some(cfg.clone());
        Ok(())
    }

    fn generate(&mut self, prompt: &str) -> Result<String, BackendError> {
        let cfg = self
            .cfg
            .as_ref()
            .ok_or_else(|| BackendError::Generation("not loaded — call load() first".into()))?;
        let model = cfg
            .model_path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "default".to_string());
        let body = serde_json::json!({
            "model": model,
            "prompt": prompt,
            "stream": false,
            "options": {
                "temperature": 0.0,
                "seed": cfg.seed as i64,
                "num_ctx": cfg.context_window,
            },
        });
        let body_bytes =
            serde_json::to_vec(&body).map_err(|e| BackendError::Generation(e.to_string()))?;
        let mut s = UnixStream::connect(&self.uds)
            .map_err(|e| BackendError::Generation(format!("connect {:?}: {e}", self.uds)))?;
        let req = format!(
            "POST /api/generate HTTP/1.1\r\n\
             Host: ollama\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n",
            body_bytes.len()
        );
        s.write_all(req.as_bytes())
            .map_err(|e| BackendError::Generation(e.to_string()))?;
        s.write_all(&body_bytes)
            .map_err(|e| BackendError::Generation(e.to_string()))?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf)
            .map_err(|e| BackendError::Generation(e.to_string()))?;
        let raw = String::from_utf8_lossy(&buf);
        let body = raw
            .split("\r\n\r\n")
            .nth(1)
            .ok_or_else(|| BackendError::Generation("no HTTP body separator".into()))?;
        let v: serde_json::Value = serde_json::from_str(body)
            .map_err(|e| BackendError::Generation(format!("parse: {e}")))?;
        Ok(v["response"].as_str().unwrap_or("").to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_https_url() {
        let r = OllamaBackend::new("https://api.ollama.ai");
        assert!(r.is_err());
    }

    #[test]
    fn refuses_http_remote() {
        let r = OllamaBackend::new("http://192.168.1.10:11434");
        assert!(r.is_err());
    }

    #[test]
    fn refuses_bare_path() {
        let r = OllamaBackend::new("/tmp/ollama.sock");
        assert!(r.is_err()); // must have unix:// prefix
    }

    #[test]
    fn accepts_uds_uri() {
        let r = OllamaBackend::new("unix:///tmp/ollama.sock");
        assert!(r.is_ok());
        assert_eq!(r.unwrap().uds, PathBuf::from("/tmp/ollama.sock"));
    }
}
