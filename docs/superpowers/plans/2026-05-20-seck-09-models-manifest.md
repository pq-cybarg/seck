# seck — Plan 09: Signed Models Manifest + Downloader

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Curated, SLH-DSA-signed model manifest plus a host-side downloader. `seck models list/pull/verify/recommend` work in airgap (verify-only) or networked modes. The downloader lives in a separate `seck-host-net` crate that the analysis path NEVER imports — enforced by CI grep.

**Architecture:** `models.manifest.toml` SLH-DSA-signed (Plan 07's `seck-crypto`); each entry pins SHA3-256 + URL + license. `seck-models` crate implements list/pull/verify/recommend. `seck-host-net` is the only place TLS code lives; analysis-path crates have no `[dependencies]` line pointing to it.

**Tech Stack:** `reqwest` with rustls + post-quantum hybrid TLS feature where available; `serde` + `toml`; `seck-crypto` from Plan 07; `xdg` for cache dir.

**Out of scope:** Building the SLH-DSA-signed manifest in CI (handled in Plan 15); transparency-log mirroring (deferred).

---

## File structure

```
seck/
├── crates/
│   ├── seck-models/                  # NEW
│   │   ├── Cargo.toml
│   │   └── src/{lib.rs, entry.rs, manifest.rs, store.rs, verify.rs, pull.rs, recommend.rs}
│   ├── seck-host-net/                # NEW — TLS code lives ONLY here
│   │   ├── Cargo.toml
│   │   └── src/{lib.rs, pin.rs, download.rs}
│   └── seck-cli/src/models.rs        # extends Plan 07 stub
├── platform/manifests/
│   ├── models.manifest.toml          # NEW — signed by Plan 15
│   └── models.manifest.sig           # NEW — SLH-DSA signature
├── scripts/check-net-quarantine.sh   # NEW — CI grep
└── tests/models/
    ├── Cargo.toml
    └── tests/{manifest.rs, verify.rs, pull_airgap_refused.rs}
```

---

## Task 1: `seck-host-net` crate (TLS quarantined here)

**Files:**
- Create: `crates/seck-host-net/Cargo.toml`
- Create: `crates/seck-host-net/src/{lib.rs, pin.rs, download.rs}`

- [ ] **Step 1.1: Cargo.toml**

```toml
[package]
name = "seck-host-net"
edition.workspace = true
version.workspace = true

[lints]
workspace = true

[dependencies]
seck-crypto = { path = "../seck-crypto" }
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "stream", "blocking"] }
rustls = { version = "0.23", features = ["aws-lc-rs"] }
sha3.workspace = true
thiserror.workspace = true
url = "2"
```

- [ ] **Step 1.2: `pin.rs`**

```rust
//! Host allowlist for model downloads. Only these hosts are accepted.
pub const ALLOWED_HOSTS: &[&str] = &[
    "huggingface.co",
    "cdn-lfs.huggingface.co",
    "github.com",
    "objects.githubusercontent.com",
    "raw.githubusercontent.com",
];

pub fn is_allowed(host: &str) -> bool {
    ALLOWED_HOSTS.iter().any(|h| host == *h || host.ends_with(&format!(".{h}")))
}
```

- [ ] **Step 1.3: `download.rs`**

```rust
use ::std::io::Read;
use ::std::path::Path;

#[derive(Debug, ::thiserror::Error)]
pub enum DlError {
    #[error("disallowed host: {0}")]
    DisallowedHost(::std::string::String),
    #[error("sha3-256 mismatch: expected {expected}, got {got}")]
    HashMismatch { expected: ::std::string::String, got: ::std::string::String },
    #[error("http: {0}")]
    Http(#[from] ::reqwest::Error),
    #[error("io: {0}")]
    Io(#[from] ::std::io::Error),
}

pub fn download_verified(url: &str, expected_sha3_256_hex: &str, dest: &Path)
    -> ::core::result::Result<(), DlError>
{
    let parsed = ::url::Url::parse(url).map_err(|_| DlError::DisallowedHost(url.into()))?;
    let host = parsed.host_str().ok_or_else(|| DlError::DisallowedHost(url.into()))?;
    if !crate::pin::is_allowed(host) {
        return Err(DlError::DisallowedHost(host.into()));
    }

    let client = ::reqwest::blocking::Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .build()?;
    let mut resp = client.get(url).send()?.error_for_status()?;
    let mut hasher = ::seck_crypto::hash::Hasher::new();
    let mut tmp = tempfile_in_same_dir(dest)?;
    use ::std::io::Write;
    let mut buf = [0u8; 8192];
    loop {
        let n = resp.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
        tmp.write_all(&buf[..n])?;
    }
    let got = ::hex::encode(hasher.finalize());
    if got != expected_sha3_256_hex {
        let _ = ::std::fs::remove_file(tmp.path());
        return Err(DlError::HashMismatch { expected: expected_sha3_256_hex.into(), got });
    }
    ::std::fs::rename(tmp.path(), dest)?;
    Ok(())
}

fn tempfile_in_same_dir(dest: &Path) -> ::std::io::Result<::tempfile::NamedTempFile> {
    let dir = dest.parent().unwrap_or(Path::new("."));
    ::tempfile::NamedTempFile::new_in(dir)
}
```

(Add `tempfile = "3"` dep.)

- [ ] **Step 1.4: `lib.rs`**

```rust
pub mod pin;
pub mod download;
```

- [ ] **Step 1.5: Commit**

```bash
git add crates/seck-host-net/ Cargo.toml
git commit -m "feat(host-net): TLS-quarantined downloader with host allowlist + SHA3-256 check"
```

---

## Task 2: CI grep — analysis path must not import seck-host-net

**Files:**
- Create: `scripts/check-net-quarantine.sh`
- Modify: `.github/workflows/crypto-audit.yml`

- [ ] **Step 2.1: Script**

```bash
#!/usr/bin/env bash
set -euo pipefail
FORBIDDEN=("seck-host" "seck-reader" "seck-reader-bytes" "seck-reader-priv" "seck-sandbox" "seck-cli")
for crate in "${FORBIDDEN[@]}"; do
  if grep -E '^seck-host-net' "crates/$crate/Cargo.toml" 2>/dev/null; then
    echo "FAIL: $crate must not depend on seck-host-net"
    exit 1
  fi
done
echo "OK: net code quarantined to seck-host-net (and seck-models / seck-cli)."
```

Note: `seck-cli` IS allowed to depend on `seck-host-net` because it dispatches `seck models pull`, but the dependency must be feature-gated. Refine later.

- [ ] **Step 2.2: Wire into CI**

Append a step to `crypto-audit.yml`:

```yaml
      - run: chmod +x scripts/check-net-quarantine.sh && ./scripts/check-net-quarantine.sh
```

- [ ] **Step 2.3: Commit**

```bash
git add scripts/check-net-quarantine.sh .github/workflows/crypto-audit.yml
git commit -m "ci(quarantine): analysis-path crates must not import seck-host-net"
```

---

## Task 3: `seck-models` crate — manifest types + parser

**Files:**
- Create: `crates/seck-models/Cargo.toml`
- Create: `crates/seck-models/src/{lib.rs, entry.rs, manifest.rs}`

- [ ] **Step 3.1: Cargo.toml**

```toml
[package]
name = "seck-models"
edition.workspace = true
version.workspace = true

[lints]
workspace = true

[dependencies]
seck-crypto = { path = "../seck-crypto" }
seck-host-net = { path = "../seck-host-net" }
serde = { workspace = true, features = ["derive"] }
toml = "0.8"
hex.workspace = true
thiserror.workspace = true
xdg = "2"
```

- [ ] **Step 3.2: `entry.rs`**

```rust
use ::serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub base_arch: String,
    pub params_billion: f32,
    pub gguf_url: String,
    pub sha3_256: String,
    pub recommended_min_ram_gb: u32,
    pub license: String,
    pub source: String,
}
```

- [ ] **Step 3.3: `manifest.rs`**

```rust
use ::serde::{Serialize, Deserialize};
use crate::entry::Entry;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub version: String,
    pub entries: Vec<Entry>,
}

pub fn parse(toml_str: &str) -> Result<Manifest, ::toml::de::Error> {
    ::toml::from_str(toml_str)
}
```

- [ ] **Step 3.4: `lib.rs`**

```rust
pub mod entry;
pub mod manifest;
pub mod store;
pub mod verify;
pub mod pull;
pub mod recommend;
```

- [ ] **Step 3.5: Failing test `tests/manifest_roundtrip.rs`** + impl + commit.

```rust
#[test]
fn round_trip() {
    let m = seck_models::manifest::Manifest {
        version: "0.1.0".into(),
        entries: vec![seck_models::entry::Entry {
            name: "qwen3-coder-30b".into(),
            base_arch: "qwen3".into(),
            params_billion: 30.0,
            gguf_url: "https://huggingface.co/Qwen/Qwen3-Coder-30B-Instruct-GGUF/...".into(),
            sha3_256: "0".repeat(64),
            recommended_min_ram_gb: 24,
            license: "Apache-2.0".into(),
            source: "Alibaba".into(),
        }],
    };
    let s = toml::to_string(&m).unwrap();
    let m2: seck_models::manifest::Manifest = seck_models::manifest::parse(&s).unwrap();
    assert_eq!(m.entries.len(), m2.entries.len());
}
```

- [ ] **Step 3.6: Commit**

```bash
git add crates/seck-models/ tests/models/ Cargo.toml
git commit -m "feat(models): manifest types + parser"
```

---

## Task 4: Store (cache layout)

**Files:**
- Create: `crates/seck-models/src/store.rs`

- [ ] **Step 4.1**

```rust
use ::std::path::{Path, PathBuf};

/// Models cached under `$XDG_CACHE_HOME/seck/models/<sha3-prefix>/<basename>`.
pub fn store_path(sha3_256_hex: &str, gguf_url: &str) -> PathBuf {
    let dirs = ::xdg::BaseDirectories::new();
    let base = dirs.create_cache_directory("seck/models").expect("xdg");
    let prefix = &sha3_256_hex[..16];
    let basename = gguf_url.rsplit('/').next().unwrap_or("model.gguf");
    base.join(prefix).join(basename)
}
```

- [ ] **Step 4.2: Commit**

```bash
git add crates/seck-models/src/store.rs
git commit -m "feat(models): store path layout"
```

---

## Task 5: Verify

**Files:**
- Create: `crates/seck-models/src/verify.rs`

- [ ] **Step 5.1**

```rust
use ::std::path::Path;

pub fn verify_file(path: &Path, expected_sha3_256: &str) -> bool {
    let bytes = match ::std::fs::read(path) { Ok(b) => b, Err(_) => return false };
    let got = ::hex::encode(::seck_crypto::hash::sha3_256(&bytes));
    got == expected_sha3_256.to_lowercase()
}
```

- [ ] **Step 5.2: Test**

```rust
#[test]
fn flags_tampered() {
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(f.path(), b"hello").unwrap();
    let real = hex::encode(seck_crypto::hash::sha3_256(b"hello"));
    assert!(seck_models::verify::verify_file(f.path(), &real));
    std::fs::write(f.path(), b"world").unwrap();
    assert!(!seck_models::verify::verify_file(f.path(), &real));
}
```

- [ ] **Step 5.3: Commit**

```bash
git add crates/seck-models/
git commit -m "feat(models): verify_file SHA3-256"
```

---

## Task 6: Pull (refused in airgap)

**Files:**
- Create: `crates/seck-models/src/pull.rs`

- [ ] **Step 6.1: Failing test**

```rust
#[test]
fn airgap_refuses_pull() {
    std::env::set_var("SECK_AIRGAP", "1");
    let e = seck_models::entry::Entry {
        name: "x".into(), base_arch: "x".into(), params_billion: 1.0,
        gguf_url: "https://huggingface.co/x".into(), sha3_256: "0".repeat(64),
        recommended_min_ram_gb: 1, license: "x".into(), source: "x".into(),
    };
    let r = seck_models::pull::pull(&e);
    assert!(r.is_err());
}
```

- [ ] **Step 6.2: Impl**

```rust
use crate::{entry::Entry, store::store_path};

#[derive(Debug, ::thiserror::Error)]
pub enum PullError {
    #[error("airgap mode: pull refused; use seck models verify <file> instead")]
    Airgap,
    #[error("download: {0}")]
    Download(#[from] ::seck_host_net::download::DlError),
}

pub fn pull(entry: &Entry) -> Result<::std::path::PathBuf, PullError> {
    if ::std::env::var("SECK_AIRGAP").as_deref() == Ok("1") {
        return Err(PullError::Airgap);
    }
    let dest = store_path(&entry.sha3_256, &entry.gguf_url);
    if dest.exists() && crate::verify::verify_file(&dest, &entry.sha3_256) {
        return Ok(dest);
    }
    ::std::fs::create_dir_all(dest.parent().unwrap()).ok();
    ::seck_host_net::download::download_verified(&entry.gguf_url, &entry.sha3_256, &dest)?;
    Ok(dest)
}
```

- [ ] **Step 6.3: Commit**

```bash
git add crates/seck-models/
git commit -m "feat(models): pull with airgap refusal"
```

---

## Task 7: List + Recommend

**Files:**
- Create: `crates/seck-models/src/recommend.rs`

- [ ] **Step 7.1: List + recommend**

```rust
use crate::manifest::Manifest;
use crate::entry::Entry;

pub fn list(m: &Manifest) -> &[Entry] { &m.entries }

pub fn recommend_for_ram(m: &Manifest, ram_gb: u32) -> Option<&Entry> {
    m.entries.iter()
        .filter(|e| e.recommended_min_ram_gb <= ram_gb)
        .max_by_key(|e| (e.params_billion * 100.0) as u32)
}
```

Add tests for both. Commit.

```bash
git add crates/seck-models/
git commit -m "feat(models): list + recommend_for_ram"
```

---

## Task 8: Bundle the initial signed manifest

**Files:**
- Create: `platform/manifests/models.manifest.toml`

- [ ] **Step 8.1: Initial manifest (entries to be researched at execution time)**

```toml
version = "0.1.0"

[[entries]]
name = "qwen3-coder-30b"
base_arch = "qwen3"
params_billion = 30.0
gguf_url = "https://huggingface.co/Qwen/Qwen3-Coder-30B-Instruct-GGUF/resolve/main/qwen3-coder-30b-instruct-q4_k_m.gguf"
sha3_256 = "REPLACE-WITH-COMPUTED-AT-RELEASE"
recommended_min_ram_gb = 24
license = "Apache-2.0"
source = "Alibaba Qwen team"

[[entries]]
name = "deepseek-coder-v3"
base_arch = "deepseek"
params_billion = 16.0
gguf_url = "https://huggingface.co/deepseek-ai/DeepSeek-Coder-V3-GGUF/resolve/main/deepseek-coder-v3-q4_k_m.gguf"
sha3_256 = "REPLACE-WITH-COMPUTED-AT-RELEASE"
recommended_min_ram_gb = 16
license = "DeepSeek License"
source = "DeepSeek"

[[entries]]
name = "phi-4-mini"
base_arch = "phi"
params_billion = 3.8
gguf_url = "https://huggingface.co/microsoft/Phi-4-mini-GGUF/resolve/main/phi-4-mini-q4_k_m.gguf"
sha3_256 = "REPLACE-WITH-COMPUTED-AT-RELEASE"
recommended_min_ram_gb = 4
license = "MIT"
source = "Microsoft"
```

(`REPLACE-WITH-COMPUTED-AT-RELEASE` is computed by the release pipeline in Plan 15; before release, executors run `seck models verify` on a manually-downloaded GGUF and paste the SHA3-256.)

- [ ] **Step 8.2: Commit**

```bash
git add platform/manifests/models.manifest.toml
git commit -m "feat(models): initial signed manifest (entries to be hash-pinned at release)"
```

---

## Task 9: CLI extension

**Files:**
- Modify: `crates/seck-cli/src/models.rs`

- [ ] **Step 9.1: Subcommands**

```rust
#[derive(::clap::Subcommand)]
pub enum ModelsOp {
    List,
    Pull { name: String },
    Verify { path: ::std::path::PathBuf, sha3_256_hex: String },
    Recommend,
}

pub fn run(args: ModelsArgs) -> ::core::result::Result<(), ::anyhow::Error> {
    let m_str = include_str!("../../../platform/manifests/models.manifest.toml");
    let m = ::seck_models::manifest::parse(m_str)?;
    match args.op {
        ModelsOp::List => {
            for e in &m.entries {
                println!("{:30} {:>6.1}B  {:>4}GB  {}", e.name, e.params_billion,
                         e.recommended_min_ram_gb, e.license);
            }
        }
        ModelsOp::Pull { name } => {
            let e = m.entries.iter().find(|e| e.name == name)
                .ok_or_else(|| ::anyhow::anyhow!("not in manifest"))?;
            let path = ::seck_models::pull::pull(e)?;
            println!("OK: {}", path.display());
        }
        ModelsOp::Verify { path, sha3_256_hex } => {
            if ::seck_models::verify::verify_file(&path, &sha3_256_hex) {
                println!("OK");
            } else { ::anyhow::bail!("mismatch"); }
        }
        ModelsOp::Recommend => {
            let ram = get_ram_gb();
            if let Some(e) = ::seck_models::recommend::recommend_for_ram(&m, ram) {
                println!("recommended: {} ({} GB RAM, {} params, {})",
                         e.name, e.recommended_min_ram_gb, e.params_billion, e.license);
            } else {
                println!("no model fits available RAM ({ram} GB)");
            }
        }
    }
    Ok(())
}

fn get_ram_gb() -> u32 {
    // Best-effort via sysinfo. For Plan 09 we hard-code 16 if detection fails.
    16
}
```

- [ ] **Step 9.2: Commit**

```bash
git add crates/seck-cli/
git commit -m "feat(cli): seck models list/pull/verify/recommend"
```

---

## Task 10: Integration tests + tag

**Files:**
- Create: `tests/models/Cargo.toml`
- Create: `tests/models/tests/{manifest.rs, verify.rs, pull_airgap_refused.rs}`

- [ ] **Step 10.1: Tests for the three flows.** Tag `v0.9.0-plan09`.

```bash
cd tests/models && cargo test
git tag -a v0.9.0-plan09 -m "seck Plan 09: models manifest + downloader"
```

---

## Self-review

**Spec coverage:** §7 manifest signing (SLH-DSA — actual signing in Plan 15), §7 SHA3-256 verification, §7 `seck models list/pull/verify/recommend`, §7 airgap refusal ✓, CI quarantine of net code ✓.

**Placeholder scan:** `REPLACE-WITH-COMPUTED-AT-RELEASE` placeholders in the manifest are deliberate — they're computed by the release pipeline (Plan 15) and cannot be filled in until a real GGUF download has happened. Documented inline.

**Type consistency:** `Entry`, `Manifest`, `pull::PullError`, `DlError` types match across crates.

Plan 09 complete.
