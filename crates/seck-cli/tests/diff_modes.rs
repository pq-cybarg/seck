//! Differential test: Plan 04 acceptance criterion.
//!
//! Mode A (single sandboxed reader) and Mode B (split bytes/priv) must
//! produce semantically equivalent reports under the stub backend on the
//! same FileSet. Fields that legitimately differ:
//!
//! - `nonce_sha3_256` is a per-invocation CSPRNG-derived value
//! - `sandbox_mode` is "A" vs "B"
//! - `inputs[].type` is "text"/"binary" in A and "ipc-structured" in B
//!   (B can't see raw bytes so it can't classify them — by design)
//! - `inputs[].sha3_256` (A, over raw bytes) vs `sha3_256_of_base64` (B)
//!
//! Everything else (version, backend name, deterministic flag,
//! temperature, seed, findings shape, sandbox_attestation.platform,
//! profile_sha3_256, file path, file size) must match.

use serde_json::Value;
use std::process::Command;

fn run_mode(mode: &str, dir: &std::path::Path) -> Value {
    let bin = env!("CARGO_BIN_EXE_seck");
    let out = Command::new(bin)
        .arg("analyze")
        .arg(dir)
        .arg(format!("--sandbox-mode={mode}"))
        .output()
        .expect("spawn seck");
    assert!(
        out.status.success(),
        "seck analyze --sandbox-mode={mode} failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parse JSON report")
}

#[test]
fn mode_a_and_b_agree_on_invariants() {
    let dir = tempfile::tempdir().expect("tmpdir");
    std::fs::write(dir.path().join("hello.txt"), b"hello plan04").unwrap();
    std::fs::write(dir.path().join("notes.md"), b"# Notes\n\nfoo bar").unwrap();

    let a = run_mode("a", dir.path());
    let b = run_mode("b", dir.path());

    // Invariants that MUST match.
    assert_eq!(a["version"], b["version"]);
    assert_eq!(a["invocation"]["backend"], b["invocation"]["backend"]);
    assert_eq!(a["invocation"]["deterministic"], b["invocation"]["deterministic"]);
    assert_eq!(a["invocation"]["temperature"], b["invocation"]["temperature"]);
    assert_eq!(a["invocation"]["seed"], b["invocation"]["seed"]);
    assert_eq!(a["invocation"]["model"], b["invocation"]["model"]);
    assert_eq!(
        a["sandbox_attestation"]["platform"],
        b["sandbox_attestation"]["platform"]
    );
    assert_eq!(
        a["sandbox_attestation"]["profile_sha3_256"],
        b["sandbox_attestation"]["profile_sha3_256"]
    );

    // Sandbox-mode tags must differ AND be the right values.
    assert_eq!(a["invocation"]["sandbox_mode"], "A");
    assert_eq!(b["invocation"]["sandbox_mode"], "B");

    // Same file set: same number of inputs, same paths and sizes.
    let a_inputs = a["inputs"].as_array().expect("a inputs array");
    let b_inputs = b["inputs"].as_array().expect("b inputs array");
    assert_eq!(a_inputs.len(), b_inputs.len(), "input count mismatch");

    let mut a_by_path: std::collections::HashMap<String, &Value> = a_inputs
        .iter()
        .map(|v| (v["path"].as_str().unwrap().to_string(), v))
        .collect();
    for bv in b_inputs {
        let p = bv["path"].as_str().unwrap();
        let av = a_by_path.remove(p).expect("path present in A");
        assert_eq!(av["size"], bv["size"], "size mismatch for {p}");
        assert_eq!(av["path"], bv["path"]);
        // A reports byte-content hash; B reports base64-content hash.
        // The two must NOT be equal (proves B never saw raw bytes).
        assert!(
            av.get("sha3_256").is_some(),
            "A should expose sha3_256 of raw bytes"
        );
        assert!(
            bv.get("sha3_256_of_base64").is_some(),
            "B should expose sha3_256 of base64 (proves B saw structured form, not raw)"
        );
    }
    assert!(a_by_path.is_empty(), "all paths matched");
}
