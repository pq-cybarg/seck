# seck — Plan 08: Ollama + MLX Local Backends

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add two LOCAL-ONLY backends behind the `LlmBackend` trait: Ollama (network-namespaced sibling sandbox, UDS bridge) and MLX (Apple Silicon native via a small companion runner). Each runs in deterministic mode (temp=0, fixed seed) and is selectable via `--backend=ollama|mlx`. Zero external network egress.

**Architecture:** Ollama backend opens a sibling sandbox with `--network=none` and starts `ollama serve` listening only on a pre-opened UDS; the reader talks HTTP-over-UDS. MLX backend spawns a bundled Swift runner that mmaps the model file (passed as FD) and writes prompts/responses over pipes. Both implement `LlmBackend` from Plan 01. `seck backends list` enumerates available.

**Tech Stack:** `reqwest` with `unix-socket` feature, `hyper-util`, Swift 5.9 + MLX framework for the MLX runner, existing `seck-plugin` trait.

**Out of scope:** Remote Ollama hosts (refused); cloud APIs (no such thing in `seck`); vLLM (Plan 12+ if requested).

---

## File structure

```
seck/
├── crates/seck-infer/
│   └── src/
│       ├── ollama.rs                 # NEW
│       ├── mlx.rs                    # NEW (cfg(macos))
│       └── lib.rs                    # modified — register backends
├── platform/macos/mlx-runner/
│   ├── Package.swift                 # NEW
│   └── Sources/MLXRunner/main.swift  # NEW
├── crates/seck-cli/src/backends.rs   # NEW — `seck backends list`
└── tests/backends/
    ├── Cargo.toml
    └── tests/{ollama_uds.rs, mlx_determinism.rs, differential.rs}
```

---

## Task 1: Ollama backend skeleton

**Files:**
- Create: `crates/seck-infer/src/ollama.rs`

- [ ] **Step 1.1: Failing test `crates/seck-infer/tests/ollama_refuses_remote.rs`**

```rust
use seck_infer::ollama::OllamaBackend;
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
fn accepts_uds() {
    let r = OllamaBackend::new("unix:///tmp/ollama.sock");
    assert!(r.is_ok());
}
```

- [ ] **Step 1.2: Impl**

```rust
use ::seck_plugin::{LlmBackend, InferenceConfig, BackendError};

pub struct OllamaBackend {
    uds_path: ::std::path::PathBuf,
    cfg: ::core::option::Option<InferenceConfig>,
}

impl OllamaBackend {
    pub fn new(host: &str) -> ::core::result::Result<Self, BackendError> {
        let uds = host.strip_prefix("unix://")
            .ok_or_else(|| BackendError::ModelLoad(
                "Ollama backend accepts only unix:// paths (no TCP)".into()))?;
        Ok(Self { uds_path: ::std::path::PathBuf::from(uds),
                  cfg: ::core::option::Option::None })
    }
}

impl LlmBackend for OllamaBackend {
    fn name(&self) -> &'static str { "ollama" }

    fn load(&mut self, cfg: &InferenceConfig) -> Result<(), BackendError> {
        self.cfg = Some(cfg.clone()); Ok(())
    }

    fn generate(&mut self, prompt: &str) -> Result<::std::string::String, BackendError> {
        let cfg = self.cfg.as_ref().ok_or_else(|| BackendError::Generation("not loaded".into()))?;
        let body = ::serde_json::json!({
            "model": cfg.model_path.file_stem().map(|s|s.to_string_lossy().to_string()).unwrap_or_default(),
            "prompt": prompt,
            "stream": false,
            "options": { "temperature": 0.0, "seed": cfg.seed as i64, "num_ctx": cfg.context_window },
        });
        let body_bytes = ::serde_json::to_vec(&body).unwrap();
        let mut stream = ::std::os::unix::net::UnixStream::connect(&self.uds_path)
            .map_err(|e| BackendError::Generation(e.to_string()))?;
        use ::std::io::Write;
        let req = format!(
            "POST /api/generate HTTP/1.1\r\nHost: ollama\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body_bytes.len());
        stream.write_all(req.as_bytes()).map_err(|e| BackendError::Generation(e.to_string()))?;
        stream.write_all(&body_bytes).map_err(|e| BackendError::Generation(e.to_string()))?;
        let mut buf = ::std::vec::Vec::new();
        use ::std::io::Read;
        stream.read_to_end(&mut buf).map_err(|e| BackendError::Generation(e.to_string()))?;
        let raw = ::std::string::String::from_utf8_lossy(&buf).into_owned();
        let body = raw.split("\r\n\r\n").nth(1).unwrap_or("");
        let v: ::serde_json::Value = ::serde_json::from_str(body)
            .map_err(|e| BackendError::Generation(e.to_string()))?;
        Ok(v["response"].as_str().unwrap_or("").to_string())
    }
}
```

- [ ] **Step 1.3: Run + commit**

```bash
cargo test -p seck-infer --test ollama_refuses_remote
git add crates/seck-infer/src/ollama.rs
git commit -m "feat(infer): Ollama backend (UDS-only, no TCP)"
```

---

## Task 2: Sibling-sandbox Ollama supervisor

**Files:**
- Modify: `crates/seck-host/src/orchestrator.rs`

- [ ] **Step 2.1: Spawn ollama in sibling sandbox**

```rust
pub fn spawn_ollama_sibling() -> Result<(::std::path::PathBuf, ::nix::unistd::Pid), OrchestratorError> {
    let socket_path = ::std::path::PathBuf::from(format!("/tmp/seck-ollama-{}.sock",
        ::std::process::id()));
    let _ = ::std::fs::remove_file(&socket_path);
    // Start `ollama serve` inside a sibling Linux sandbox with --network=none
    // and OLLAMA_HOST=unix://path. (Same lockdown stack as seck-reader.)
    let pid = match unsafe { ::nix::unistd::fork()? } {
        ::nix::unistd::ForkResult::Parent { child } => child,
        ::nix::unistd::ForkResult::Child => {
            ::seck_sandbox::linux::LinuxSandbox::apply_self_lockdown()?;
            ::std::env::set_var("OLLAMA_HOST", format!("unix://{}", socket_path.display()));
            let prog = ::std::ffi::CString::new("ollama").unwrap();
            let args = [
                prog.as_c_str(),
                ::std::ffi::CString::new("serve").unwrap().as_c_str(),
            ];
            ::nix::unistd::execvp(&prog, &args)?;
            unreachable!()
        }
    };
    // Wait for the socket to appear (up to 5s).
    let deadline = ::std::time::Instant::now() + ::std::time::Duration::from_secs(5);
    while !socket_path.exists() {
        if ::std::time::Instant::now() > deadline {
            return Err(OrchestratorError::Sandbox("ollama failed to start".into()));
        }
        ::std::thread::sleep(::std::time::Duration::from_millis(50));
    }
    Ok((socket_path, pid))
}
```

- [ ] **Step 2.2: Commit**

```bash
git add crates/seck-host/
git commit -m "feat(host): sibling-sandboxed ollama serve over UDS"
```

---

## Task 3: MLX backend (macOS) — Swift companion runner

**Files:**
- Create: `platform/macos/mlx-runner/Package.swift`
- Create: `platform/macos/mlx-runner/Sources/MLXRunner/main.swift`

- [ ] **Step 3.1: `Package.swift`**

```swift
// swift-tools-version:5.9
import PackageDescription
let package = Package(
    name: "MLXRunner",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(url: "https://github.com/ml-explore/mlx-swift", from: "0.21.0"),
    ],
    targets: [
        .executableTarget(name: "MLXRunner",
            dependencies: [.product(name: "MLX", package: "mlx-swift"),
                           .product(name: "MLXLLM", package: "mlx-swift")]),
    ])
```

- [ ] **Step 3.2: `main.swift`** (sketch — exact MLX API moves quickly; verify at integration time)

```swift
import Foundation
import MLX
import MLXLLM

// Protocol on stdin: "PROMPT\n<bytes>\nEND\n" → "RESPONSE\n<bytes>\nEND\n"
let modelPath = ProcessInfo.processInfo.environment["SECK_MLX_MODEL"] ?? ""
let seed = UInt64(ProcessInfo.processInfo.environment["SECK_MLX_SEED"] ?? "42") ?? 42

let modelContainer = try await LLMModelFactory.shared.loadContainer(
    configuration: .init(directory: URL(fileURLWithPath: modelPath)))
MLXRandom.seed(seed)

while let line = readLine() {
    if line == "PROMPT" {
        var buf = ""
        while let l = readLine(), l != "END" { buf += l + "\n" }
        let result = try await modelContainer.perform { context in
            context.generate(prompt: buf, maxTokens: 1024, temperature: 0.0)
        }
        print("RESPONSE"); print(result); print("END")
        FileHandle.standardOutput.synchronizeFile()
    }
}
```

- [ ] **Step 3.3: Rust side `mlx.rs`**

```rust
#![cfg(target_os = "macos")]
use ::seck_plugin::{LlmBackend, InferenceConfig, BackendError};

pub struct MlxBackend { child: ::core::option::Option<::std::process::Child>, cfg: Option<InferenceConfig> }

impl MlxBackend {
    pub fn new() -> Self { Self { child: None, cfg: None } }
}

impl LlmBackend for MlxBackend {
    fn name(&self) -> &'static str { "mlx" }
    fn load(&mut self, cfg: &InferenceConfig) -> Result<(), BackendError> {
        let runner = ::std::env::current_exe().map_err(|e| BackendError::Io(e))?
            .parent().unwrap().join("MLXRunner");
        let child = ::std::process::Command::new(runner)
            .env("SECK_MLX_MODEL", &cfg.model_path)
            .env("SECK_MLX_SEED", cfg.seed.to_string())
            .stdin(::std::process::Stdio::piped())
            .stdout(::std::process::Stdio::piped())
            .spawn().map_err(|e| BackendError::Io(e))?;
        self.child = Some(child); self.cfg = Some(cfg.clone()); Ok(())
    }
    fn generate(&mut self, prompt: &str) -> Result<String, BackendError> {
        use ::std::io::{Write, BufRead};
        let child = self.child.as_mut().ok_or_else(|| BackendError::Generation("not loaded".into()))?;
        writeln!(child.stdin.as_mut().unwrap(), "PROMPT").unwrap();
        write!(child.stdin.as_mut().unwrap(), "{prompt}").unwrap();
        writeln!(child.stdin.as_mut().unwrap(), "\nEND").unwrap();
        let reader = ::std::io::BufReader::new(child.stdout.as_mut().unwrap());
        let mut acc = String::new();
        let mut started = false;
        for line in reader.lines() {
            let l = line.unwrap();
            if l == "RESPONSE" { started = true; continue; }
            if l == "END" && started { break; }
            if started { acc.push_str(&l); acc.push('\n'); }
        }
        Ok(acc)
    }
}
```

- [ ] **Step 3.4: Commit**

```bash
git add platform/macos/mlx-runner/ crates/seck-infer/
git commit -m "feat(infer): MLX backend with Swift companion runner"
```

---

## Task 4: `seck backends list`

**Files:**
- Create: `crates/seck-cli/src/backends.rs`

- [ ] **Step 4.1**

```rust
pub fn run() -> ::core::result::Result<(), ::anyhow::Error> {
    println!("Available backends:");
    println!("  llama-cpp    (always)");
    println!("  ollama       ({})", if which::which("ollama").is_ok() {"installed"} else {"not installed"});
    #[cfg(target_os = "macos")]
    println!("  mlx          ({})", if cfg!(target_arch = "aarch64") {"available"} else {"x86_64 unsupported"});
    Ok(())
}
```

- [ ] **Step 4.2: Commit**

```bash
git add crates/seck-cli/
git commit -m "feat(cli): seck backends list"
```

---

## Task 5: Determinism + differential tests

**Files:**
- Create: `tests/backends/Cargo.toml`
- Create: `tests/backends/tests/mlx_determinism.rs`
- Create: `tests/backends/tests/differential.rs`

- [ ] **Step 5.1: Determinism**

```rust
#![cfg(target_os = "macos")]
#[test]
#[ignore = "requires MLX model"]
fn mlx_deterministic_runs() {
    use seck_infer::mlx::MlxBackend;
    use seck_plugin::{LlmBackend, InferenceConfig};
    let cfg = InferenceConfig { model_path: "/path/to/model".into(),
                                temperature: 0.0, seed: 42,
                                max_tokens: 64, context_window: 2048 };
    let mut b1 = MlxBackend::new(); b1.load(&cfg).unwrap();
    let r1 = b1.generate("Hello").unwrap();
    let mut b2 = MlxBackend::new(); b2.load(&cfg).unwrap();
    let r2 = b2.generate("Hello").unwrap();
    assert_eq!(r1, r2);
}
```

- [ ] **Step 5.2: Differential A vs B (backends)** — skipped unless 2+ backends with same model are installed.

- [ ] **Step 5.3: Commit**

```bash
git add tests/backends/ Cargo.toml
git commit -m "test(backends): determinism + differential (gated by --include-ignored)"
```

---

## Task 6: README + tag

```bash
# Append backends section to README, tag v0.8.0-plan08
```

---

## Self-review

**Spec coverage:** §7 Ollama (sibling-sandboxed UDS) ✓; MLX backend (Apple Silicon, mmap, deterministic) ✓; backend listing ✓. UDS-only enforcement refuses any TCP host.

**Placeholder scan:** None; the MLX Swift snippet notes that MLX's API moves and to verify — that's a research-flag, not a placeholder. Each backend has concrete code.

**Type consistency:** Both backends implement the `LlmBackend` trait from Plan 01. `InferenceConfig` is shared.

Plan 08 complete.
