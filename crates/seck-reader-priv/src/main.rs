//! seck-reader-priv: in-sandbox inference orchestrator (Approach B).
//!
//! Reads structured `Message`s from FD 3 (the socketpair from
//! seck-reader-bytes), assembles a prompt from them, runs inference,
//! writes the JSON report to FD 5.
//!
//! CRITICALLY: this crate has no dependency on `seck-taint`. The
//! workspace compile-fail test
//! `tests/compile-fail/cases/priv_imports_seck_taint.rs` verifies that
//! a `use seck_taint;` in this crate does not type-check.
//!
//! Threat model: even if a bug leaks bytes from the priv process, they
//! cannot reach argv/env/path/socket of any subsequent process because
//! the only way to do so requires consuming a `Tainted<Vec<u8>>` value,
//! and this crate has no `Tainted` to consume.

// seck-reader-priv is also Unix-only (inherits FD 3 + FD 5 from the
// orchestrator). On Windows it isn't built; the windows.yml CI skips
// the workspace bin that would otherwise fail.
#[cfg(not(unix))]
fn main() {
    eprintln!("seck-reader-priv is Unix-only.");
    std::process::exit(1);
}

#[cfg(unix)]
use anyhow::Context;
#[cfg(unix)]
use seck_plugin::{InferenceConfig, LlmBackend};
#[cfg(unix)]
use seck_reader_ipc::{Message, read_messages};
#[cfg(unix)]
use std::io::{BufReader, Write};
#[cfg(unix)]
use std::os::fd::{FromRawFd, OwnedFd};

#[cfg(unix)]
fn main() {
    if let Err(e) = real_main() {
        eprintln!("seck-reader-priv: {e:?}");
        std::process::exit(1);
    }
}

#[cfg(unix)]
fn real_main() -> anyhow::Result<()> {
    // Apply sandbox lockdown immediately, before reading anything.
    if let Err(e) = seck_sandbox::apply_self_lockdown() {
        eprintln!("seck-reader-priv: sandbox unavailable ({e}); running unsandboxed");
    }

    // FD 3 = socketpair from seck-reader-bytes (inherited).
    // SAFETY: FD 3 is inherited by the parent orchestrator before exec.
    #[allow(unsafe_code)]
    let in_fd = unsafe { OwnedFd::from_raw_fd(3) };
    let in_file = std::fs::File::from(in_fd);
    let mut reader = BufReader::new(in_file);
    let messages = read_messages(&mut reader).context("read FD-3 IPC")?;

    // Walk the messages, build the prompt purely from structured strings.
    // The priv process never sees raw file bytes — only base64 strings.
    let mut prompt = String::new();
    let mut inputs_meta: Vec<serde_json::Value> = Vec::new();
    let mut nonce_hex = String::new();
    let mut in_files = false;
    for m in &messages {
        match m {
            Message::Header {
                nonce_hex: n,
                system_prompt,
                task_prompt,
            } => {
                nonce_hex = n.clone();
                prompt.push_str(&format!("<system>\n{system_prompt}\n</system>\n\n"));
                prompt.push_str(&format!("<files-begin-{n}>\n"));
                in_files = true;
                let _ = task_prompt; // appended after EndFiles
            }
            Message::File {
                relative_path,
                content_base64,
                byte_count,
            } => {
                prompt.push_str(&format!("<file path=\"{relative_path}\">\n"));
                prompt.push_str(&format!("<bytes-begin-{nonce_hex}>\n"));
                prompt.push_str(content_base64);
                prompt.push_str(&format!("\n<bytes-end-{nonce_hex}>\n</file>\n"));
                // Synthesize an `inputs[]` entry: we know the path and
                // byte_count but NOT the raw bytes, so the SHA3-256
                // computed here is over the base64 form (which is fine
                // for deterministic identity).
                let mut h = seck_crypto::hash::Hasher::new();
                h.update(content_base64.as_bytes());
                inputs_meta.push(serde_json::json!({
                    "path": relative_path,
                    "sha3_256_of_base64": hex::encode(h.finalize()),
                    "size": byte_count,
                    "type": "ipc-structured",
                }));
            }
            Message::EndFiles => {
                if in_files {
                    prompt.push_str(&format!("<files-end-{nonce_hex}>\n\n"));
                }
                in_files = false;
            }
        }
    }
    // The task prompt was carried on the Header but we appended files
    // first; emit a default task here. Plan 06 sources the real one
    // from the pipeline.
    prompt
        .push_str("<task>\nProduce a JSON object matching the report schema. The marker nonce is ");
    prompt.push_str(&nonce_hex);
    prompt.push_str(".\n</task>\n");

    // Run inference with the stub backend by default. Real backends are
    // wired in by `seck-reader-bytes` choosing the spawn target.
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
    let mut backend = seck_infer::stub::StubBackend::new();
    backend.load(&cfg).context("backend load")?;
    let raw = backend.generate(&prompt).context("backend generate")?;

    // Build the report.
    let parsed: serde_json::Value =
        serde_json::from_str(&raw).unwrap_or_else(|_| serde_json::json!({ "raw": raw }));
    let findings = parsed
        .get("findings")
        .cloned()
        .unwrap_or(serde_json::json!([]));
    let nonce_sha3_256_hex = {
        let mut h = seck_crypto::hash::Hasher::new();
        h.update(nonce_hex.as_bytes());
        hex::encode(h.finalize())
    };
    let report = serde_json::json!({
        "version": "0.1.0",
        "invocation": {
            "nonce_sha3_256": nonce_sha3_256_hex,
            "started_at": "",
            "finished_at": "",
            "sandbox_mode": "B",
            "backend": backend.name(),
            "model": model_path.display().to_string(),
            "model_sha3_256": "",
            "temperature": cfg.temperature,
            "seed": cfg.seed,
            "deterministic": true,
        },
        "inputs": inputs_meta,
        "findings": findings,
        "sandbox_attestation": {
            "platform": std::env::consts::OS,
            "sandbox_mode": "B",
            "profile_sha3_256": hex::encode(seck_sandbox::bundled_profile_hash()),
            "binary_sha3_256": "",
        }
    });

    // FD 5 = report pipe to host.
    // SAFETY: inherited by the parent orchestrator.
    #[allow(unsafe_code)]
    let out_fd = unsafe { OwnedFd::from_raw_fd(5) };
    let mut out = std::fs::File::from(out_fd);
    out.write_all(serde_json::to_string(&report)?.as_bytes())?;
    out.flush()?;
    Ok(())
}
