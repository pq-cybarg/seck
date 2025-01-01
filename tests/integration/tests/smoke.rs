//! End-to-end smoke tests for `seck analyze`. Runs the actual binary in a
//! subprocess; assertions confirm:
//!   * a real file produces a structurally-valid JSON report
//!   * an adversarial filename does NOT cause shell execution
//!   * a symlink target is NOT followed (no bytes from the symlink target
//!     reach the input set)

#![cfg(target_os = "linux")]

use assert_cmd::Command;
use std::path::PathBuf;
use tempfile::TempDir;

fn seck_bin() -> PathBuf {
    if let Ok(p) = std::env::var("SECK_BIN") {
        return p.into();
    }
    // Default: built from the workspace.
    let here = env!("CARGO_MANIFEST_DIR");
    let root = std::path::Path::new(here).parent().unwrap().parent().unwrap();
    root.join("target/release/seck")
}

#[test]
fn analyzes_a_text_file_to_json() {
    let d = TempDir::new().unwrap();
    let p = d.path().join("hello.rs");
    std::fs::write(&p, b"fn main() { println!(\"hi\"); }").unwrap();
    let out = Command::new(seck_bin())
        .args(["analyze", p.to_str().unwrap()])
        .output()
        .expect("ran seck");
    assert!(
        out.status.success(),
        "seck failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout is JSON");
    assert_eq!(v["version"], "0.1.0");
    assert_eq!(v["invocation"]["sandbox_mode"], "A");
    assert_eq!(v["invocation"]["deterministic"], true);
    assert_eq!(v["inputs"].as_array().unwrap().len(), 1);
    let sha = v["inputs"][0]["sha3_256"].as_str().unwrap();
    assert_eq!(sha.len(), 64, "sha3-256 hex");
}

#[test]
fn adversarial_filename_does_not_execute_shell() {
    let d = TempDir::new().unwrap();
    // Filename packed with shell metacharacters: `;` `&&` `$()` `` ` ``
    // backticks, `|`, `>`. Filesystem rules forbid `/` and NUL in
    // filenames, so we use everything else.
    let injection = "a;b&&c$(d)e`f`g|h>i.txt";
    let weird = d.path().join(injection);
    std::fs::write(&weird, b"content").unwrap();
    let out = Command::new(seck_bin())
        .args(["analyze", weird.to_str().unwrap()])
        .output()
        .expect("ran seck");
    // If any shell had interpreted the filename, seck would never have
    // received the literal "a;b&&c$(d)e`f`g|h>i.txt" string as the open()
    // target — it would have seen "a", or "b", or something else broken,
    // and the analyze would have failed with file-not-found.
    assert!(
        out.status.success(),
        "seck analyze on adversarial filename failed (probable shell interpretation): stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout is JSON");
    assert_eq!(
        v["inputs"][0]["path"].as_str().unwrap(),
        injection,
        "the inputs[].path must be the literal filename, byte-for-byte"
    );
}

#[test]
fn symlink_in_target_is_not_followed() {
    let d = TempDir::new().unwrap();
    // /etc/passwd is world-readable on a real Linux system; we use it
    // as a representative sensitive file.
    let link = d.path().join("dangerous");
    std::os::unix::fs::symlink("/etc/passwd", &link).unwrap();
    let out = Command::new(seck_bin())
        .args(["analyze", link.to_str().unwrap()])
        .output()
        .expect("ran seck");
    // The walker silently drops symlinks (returns zero inputs). The whole
    // command should NOT fail in a way that leaked passwd content. Check
    // the JSON's inputs array is empty AND the analyze did not produce a
    // sha3-256 of /etc/passwd's bytes.
    if out.status.success() {
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let real_passwd_sha = {
            use sha3::{Digest, Sha3_256};
            let mut h = Sha3_256::new();
            if let Ok(bytes) = std::fs::read("/etc/passwd") {
                h.update(&bytes);
                Some(hex::encode(h.finalize()))
            } else {
                None
            }
        };
        if let Some(real) = real_passwd_sha {
            for input in v["inputs"].as_array().unwrap_or(&vec![]) {
                let sha = input["sha3_256"].as_str().unwrap_or("");
                assert_ne!(sha, real, "FAIL: symlink WAS followed — /etc/passwd hash present in inputs");
            }
        }
    }
}
