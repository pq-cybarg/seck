//! `seck-reader` — the in-sandbox reader. Spawned by `seck` via fork+exec.
//! Reads frames from FD 3, runs the LLM backend (stub or real), writes the
//! JSON report to FD 5.

use anyhow::Context;
use rand::TryRngCore;
use seck_plugin::{InferenceConfig, LlmBackend};
use sha3::{Digest, Sha3_256};
use std::io::{BufReader, Write};
use std::os::fd::{FromRawFd, OwnedFd};

mod prompt {
    pub use seck_reader::prompt::*;
}
mod protocol {
    pub use seck_reader::protocol::*;
}

fn main() {
    if let Err(e) = real_main() {
        eprintln!("seck-reader error: {e:?}");
        std::process::exit(1);
    }
}

fn real_main() -> anyhow::Result<()> {
    // 1. Apply sandbox lockdown immediately. The platform-neutral helper
    // routes to Linux Landlock+prctl on Linux, macOS Seatbelt on macOS,
    // and a no-op stub elsewhere.
    if let Err(e) = seck_sandbox::apply_self_lockdown() {
        eprintln!("seck-reader: sandbox unavailable ({e}); running unsandboxed");
    }

    // 2. Read frames from FD 3.
    // SAFETY: FD 3 is inherited from the parent (the host orchestrator
    // explicitly dup2'd a pipe into FD 3 before execvp).
    #[allow(unsafe_code)]
    let stdin_fd = unsafe { OwnedFd::from_raw_fd(3) };
    let stdin_file = std::fs::File::from(stdin_fd);
    let mut reader = BufReader::new(stdin_file);
    let frames = protocol::read_frames(&mut reader).context("read FD-3 frames")?;

    // 3. Per-run nonce (256 bits CSPRNG).
    let mut nonce = [0u8; 32];
    rand::rng()
        .try_fill_bytes(&mut nonce)
        .context("CSPRNG fill")?;

    // 4. Assemble prompt.
    let assembled = prompt::assemble(&prompt::AssembleConfig { nonce }, &frames);

    // 5. Inference config (Plan 01 hardwires defaults; Plan 06 wires --model-{role}).
    let model_path: std::path::PathBuf = std::env::var("SECK_MODEL_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("(none — stub backend)"));
    let cfg = InferenceConfig {
        model_path: model_path.clone(),
        temperature: 0.0,
        seed: 42,
        max_tokens: 1024,
        context_window: 8192,
    };

    // 6. Run inference (stub by default — see seck-infer::stub).
    let mut backend = seck_infer::stub::StubBackend::new();
    backend.load(&cfg).context("backend load")?;
    let raw = backend.generate(&assembled).context("backend generate")?;

    // 7. Build the report.
    let nonce_hash = {
        let mut h = Sha3_256::new();
        h.update(nonce);
        hex::encode(h.finalize())
    };
    let inputs: Vec<serde_json::Value> = frames
        .iter()
        .map(|f| {
            let mut h = Sha3_256::new();
            h.update(&f.bytes);
            serde_json::json!({
                "path": f.relative_path,
                "sha3_256": hex::encode(h.finalize()),
                "size": f.bytes.len(),
                "type": if std::str::from_utf8(&f.bytes).is_ok() { "text" } else { "binary" },
            })
        })
        .collect();
    let parsed: serde_json::Value =
        serde_json::from_str(&raw).unwrap_or_else(|_| serde_json::json!({"raw": raw}));
    let findings = parsed.get("findings").cloned().unwrap_or(serde_json::json!([]));

    let report = serde_json::json!({
        "version": "0.1.0",
        "invocation": {
            "nonce_sha3_256": nonce_hash,
            "started_at": "",
            "finished_at": "",
            "sandbox_mode": "A",
            "backend": backend.name(),
            "model": model_path.display().to_string(),
            "model_sha3_256": "",
            "temperature": cfg.temperature,
            "seed": cfg.seed,
            "deterministic": true,
        },
        "inputs": inputs,
        "findings": findings,
        "sandbox_attestation": {
            "platform": std::env::consts::OS,
            "sandbox_mode": "A",
            "profile_sha3_256": hex::encode(seck_sandbox::bundled_profile_hash()),
            "binary_sha3_256": "",
        }
    });

    // 8. Write to FD 5.
    // SAFETY: FD 5 is inherited from the parent for the report pipe.
    #[allow(unsafe_code)]
    let report_fd = unsafe { OwnedFd::from_raw_fd(5) };
    let mut report_file = std::fs::File::from(report_fd);
    report_file.write_all(serde_json::to_string(&report)?.as_bytes())?;
    report_file.flush()?;
    Ok(())
}
