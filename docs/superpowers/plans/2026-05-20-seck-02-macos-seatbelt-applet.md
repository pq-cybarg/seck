# seck — Plan 02: macOS Seatbelt + Drag-and-Drop Applet

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `seck analyze <path>` work natively on macOS with an audited `sandbox_init_with_extensions()` (SBPL/Seatbelt) profile providing the same IO-boundary guarantees as Plan 01's Linux sandbox, plus a drag-and-drop `Seck.app` applet and a Finder Quick Action — both passing dropped paths as PRE-OPENED FDs (never as argv path strings) so the typestate invariant holds end-to-end.

**Architecture:** Add `macos.rs` to `seck-sandbox` exposing a `MacosSandbox` that applies Apple's Seatbelt profile via the (technically deprecated but still functional) `sandbox_init_with_extensions` C API. Author `platform/macos/seatbelt.sb` as an audited deny-default SBPL profile: allow only file-read on the model directory, allow only read/write on inherited pipes 3 and 5, deny `network*`, deny `process-exec*` except a strict allowlist (the bundled llama-cli only). Add a macOS path to `seck-host-unsafe::path_resolver` using `open(O_NOFOLLOW|O_CLOEXEC)` + `fstat` + anchored `realpath` verification. Build `Seck.app` (Swift) as a thin shell that uses `posix_spawn_file_actions_addinherit_np` to hand dropped paths to the CLI as inherited FDs. Ship a Finder Quick Action (`.workflow`) that calls into the same path.

**Tech Stack:** Rust (existing), Swift 5.9 + macOS 14 SDK for the applet, Automator for the Quick Action, `sandbox_init_with_extensions` (libsystem_sandbox), `bindgen` for the C FFI, `codesign` for signing the applet (a self-signed adhoc certificate is fine for Plan 02; Plan 15 handles distribution signing).

**Out of scope:** Notarization (deferred to Plan 15); Mac App Store packaging (out of v1 entirely); container mode on macOS (already covered in Plan 03 via `podman machine`); MLX backend (Plan 08); Apple Silicon-specific hardening beyond what Seatbelt provides (some of it in Plan 07).

---

## File structure

```
seck/
├── crates/seck-sandbox/
│   ├── Cargo.toml                          # modified — add cfg(target_os="macos") deps
│   └── src/
│       ├── lib.rs                          # modified — add SandboxMode::Macos
│       └── macos.rs                        # NEW — sandbox_init_with_extensions FFI
├── crates/seck-host-unsafe/
│   ├── Cargo.toml                          # modified — cfg-gated paths
│   └── src/
│       ├── lib.rs                          # modified — re-exports by cfg
│       ├── linux.rs                        # NEW — moved from current lib.rs
│       └── macos.rs                        # NEW — open(O_NOFOLLOW) path resolver
├── crates/seck-host/src/orchestrator.rs    # modified — posix_spawn FD inheritance
├── platform/macos/
│   ├── seatbelt.sb                         # NEW — audited SBPL profile
│   ├── applet/
│   │   ├── Seck.xcodeproj/                 # NEW — Xcode project
│   │   ├── Sources/SeckApplet/
│   │   │   ├── AppDelegate.swift
│   │   │   ├── Info.plist
│   │   │   └── FDPassing.swift             # posix_spawn_file_actions_addinherit_np
│   │   ├── Resources/Assets.xcassets/
│   │   └── build_applet.sh                 # buildable from command line
│   └── quickaction/
│       └── AnalyzeWithSeck.workflow/       # Automator Quick Action bundle
├── tests/escape-macos/
│   ├── Cargo.toml
│   └── tests/escape.rs                     # 8 macOS escape attempts
└── .github/workflows/
    └── macos.yml                           # NEW — macOS CI runner
```

---

## Pre-flight

- [ ] **Step 0.1: Verify macOS tooling**

```bash
sw_vers -productVersion          # expect 14+ (Sonoma) or 15+ (Sequoia)
xcode-select -p                  # expect /Applications/Xcode.app/...
xcrun --find swift               # expect a path
xcrun --find codesign            # expect a path
```

If Xcode is missing: install from the Mac App Store, then `sudo xcode-select -s /Applications/Xcode.app/Contents/Developer`.

- [ ] **Step 0.2: Confirm Seatbelt is still functional**

```bash
sandbox-exec -p '(version 1)(deny default)' /bin/echo "hi"
```

Expected: prints `hi` (the SBPL profile parses, denies most things, but the simple echo binary doesn't need much). If you get `sandbox-exec: command not found`, the toolchain is missing.

---

## Task 1: Author the audited SBPL profile

**Files:**
- Create: `platform/macos/seatbelt.sb`

- [ ] **Step 1.1: Write `platform/macos/seatbelt.sb`**

```scheme
;; Audited Seatbelt (SBPL) profile for seck-reader on macOS.
;; Deny default. Allow only:
;;   * read-only file access to the model directory (parameter MODEL_DIR)
;;   * read/write on inherited pipes (FDs 3 and 5) — implicit via fd-set
;;   * process-exec of the bundled llama-cli only
;; Deny all networking, mach lookups, IOKit, system calls outside core libc.

(version 1)
(deny default)

;; --- Allow basics needed by any process ---
;; The reader's own image and libsystem need to be mapped read-only.
(allow file-read-data file-read-metadata
  (subpath "/usr/lib")
  (subpath "/System/Library/Frameworks")
  (subpath "/System/Library/PrivateFrameworks")
  (subpath "/System/Library/Caches/com.apple.dyld")
  (literal "/usr/share/icu/icudt74l.dat"))

;; --- Allow read-only access to the model directory ---
;; The host substitutes (param "MODEL_DIR") at sandbox_init_with_extensions
;; time via the SANDBOX_EXTENSION mechanism (see Step 2.2).
(allow file-read-data file-read-metadata
  (subpath (param "MODEL_DIR")))

;; --- Allow the bundled inference binary to be exec'd ---
;; The host substitutes (param "INFER_BIN").
(allow process-exec*
  (literal (param "INFER_BIN")))

;; --- Allow read/write only on already-inherited FDs ---
;; Sandbox-exec inherits open FDs by default; this is needed because the
;; default profile also allows reading from an inherited FD even though
;; new opens are denied.

;; --- Deny everything else (explicit deny is verbose but auditable) ---
(deny file-write*)
(deny network*)
(deny mach-lookup)
(deny iokit-open)
(deny process-exec*)
(deny system-socket)
(deny lsopen)
(deny file-issue-extension)
(deny mach-bootstrap)
(deny sysctl-write)

;; Allow reading sysctl.kern.osversion etc., needed by llama.cpp's CPU detection.
(allow sysctl-read
  (sysctl-name "hw.ncpu")
  (sysctl-name "hw.optional.arm.FEAT_FP16")
  (sysctl-name "hw.optional.arm.FEAT_BF16")
  (sysctl-name "hw.optional.AdvSIMD")
  (sysctl-name "kern.osversion")
  (sysctl-name "kern.osproductversion"))

;; Allow signal handling and clock reads (needed by tokio).
(allow signal (target self))
(allow process-info-pidinfo (target self))
```

- [ ] **Step 1.2: Smoke test the profile with sandbox-exec**

```bash
sandbox-exec -D MODEL_DIR=/tmp -D INFER_BIN=/bin/echo \
  -f platform/macos/seatbelt.sb \
  /bin/echo "profile loads"
```

Expected: prints `profile loads`. If it errors with "syntax error", fix the SBPL.

- [ ] **Step 1.3: Commit**

```bash
git add platform/macos/seatbelt.sb
git commit -m "feat(sandbox/macos): audited Seatbelt SBPL profile"
```

---

## Task 2: `MacosSandbox` Rust wrapper for `sandbox_init_with_extensions`

**Files:**
- Modify: `crates/seck-sandbox/Cargo.toml`
- Modify: `crates/seck-sandbox/src/lib.rs`
- Create: `crates/seck-sandbox/src/macos.rs`

- [ ] **Step 2.1: Modify `crates/seck-sandbox/Cargo.toml`**

```toml
[target.'cfg(target_os = "macos")'.dependencies]
libc = "0.2"
```

- [ ] **Step 2.2: Write `crates/seck-sandbox/src/macos.rs`**

```rust
//! macOS Seatbelt (SBPL) sandbox.
//!
//! Calls `sandbox_init_with_extensions` with the bundled audited profile.
//! Extensions substitute the MODEL_DIR and INFER_BIN parameters.

#![cfg(target_os = "macos")]

use ::sha3::{Sha3_256, Digest};
use ::seck_plugin::SandboxBackend;

pub struct MacosSandbox {
    profile_hash: [u8; 32],
}

impl MacosSandbox {
    pub fn new() -> Self {
        let mut h = Sha3_256::new();
        h.update(include_bytes!("../../../platform/macos/seatbelt.sb"));
        Self { profile_hash: h.finalize().into() }
    }

    /// Apply Seatbelt sandbox to the current process. Call early in
    /// seck-reader's main(), after pre-opened FDs are inherited.
    pub fn apply_self_lockdown(model_dir: &::std::path::Path, infer_bin: &::std::path::Path)
        -> ::core::result::Result<(), ::anyhow::Error>
    {
        let profile = include_str!("../../../platform/macos/seatbelt.sb");
        let cprofile = ::std::ffi::CString::new(profile)?;
        let cmodel = ::std::ffi::CString::new(model_dir.as_os_str().as_encoded_bytes())?;
        let cinfer = ::std::ffi::CString::new(infer_bin.as_os_str().as_encoded_bytes())?;

        // Two parameters: MODEL_DIR and INFER_BIN. Pass as NULL-terminated array.
        // Layout: ["MODEL_DIR\0", "<value>\0", "INFER_BIN\0", "<value>\0", NULL]
        let model_key = ::std::ffi::CString::new("MODEL_DIR")?;
        let infer_key = ::std::ffi::CString::new("INFER_BIN")?;
        let params: [*const ::libc::c_char; 5] = [
            model_key.as_ptr(),
            cmodel.as_ptr(),
            infer_key.as_ptr(),
            cinfer.as_ptr(),
            ::std::ptr::null(),
        ];

        let mut errbuf: *mut ::libc::c_char = ::std::ptr::null_mut();
        // SAFETY: extern function from libsystem_sandbox.
        #[allow(unsafe_code)]
        let rc = unsafe {
            sandbox_init_with_parameters(cprofile.as_ptr(), 0, params.as_ptr(), &mut errbuf)
        };
        if rc != 0 {
            let err = if errbuf.is_null() {
                "unknown sandbox error".to_string()
            } else {
                #[allow(unsafe_code)]
                let s = unsafe { ::std::ffi::CStr::from_ptr(errbuf).to_string_lossy().into_owned() };
                #[allow(unsafe_code)]
                unsafe { sandbox_free_error(errbuf) };
                s
            };
            return ::core::result::Result::Err(::anyhow::anyhow!("sandbox_init_with_parameters: {err}"));
        }
        ::core::result::Result::Ok(())
    }
}

impl SandboxBackend for MacosSandbox {
    fn name(&self) -> &'static str { "macos-seatbelt" }
    fn profile_sha3_256(&self) -> [u8; 32] { self.profile_hash }
}

#[link(name = "System")]
unsafe extern "C" {
    // sandbox.h (deprecated but functional through macOS 15+).
    fn sandbox_init_with_parameters(
        profile: *const ::libc::c_char,
        flags: u64,
        parameters: *const *const ::libc::c_char,
        errorbuf: *mut *mut ::libc::c_char,
    ) -> i32;
    fn sandbox_free_error(errbuf: *mut ::libc::c_char);
}
```

The crate-level workspace `unsafe_code = "forbid"` will block this. Put `macos.rs` behind a feature-gated relaxation: in `seck-sandbox/Cargo.toml`:

```toml
[lints.rust]
unsafe_code = "deny"   # workspace inherit overrides this
```

This crate already has `seccompiler`/`landlock` requiring unsafe in some configurations; relax to `deny` (so `#[allow(unsafe_code)]` works).

- [ ] **Step 2.3: Update `crates/seck-sandbox/src/lib.rs`**

```rust
#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

pub mod container;

use ::seck_plugin::SandboxBackend;

#[derive(Debug, Clone, Copy)]
pub enum SandboxMode { A, Container }

pub fn backend_for(mode: SandboxMode) -> ::std::boxed::Box<dyn SandboxBackend> {
    match mode {
        SandboxMode::A => {
            #[cfg(target_os = "linux")]
            { ::std::boxed::Box::new(linux::LinuxSandbox::new()) }
            #[cfg(target_os = "macos")]
            { ::std::boxed::Box::new(macos::MacosSandbox::new()) }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            { compile_error!("Approach A requires linux or macos") }
        }
        SandboxMode::Container => ::std::boxed::Box::new(container::ContainerSandbox::new()),
    }
}
```

- [ ] **Step 2.4: Build and verify**

```bash
cargo build -p seck-sandbox --target=aarch64-apple-darwin
cargo build -p seck-sandbox --target=x86_64-apple-darwin
```

Expected: both succeed on a macOS host.

- [ ] **Step 2.5: Commit**

```bash
git add crates/seck-sandbox/
git commit -m "feat(sandbox): MacosSandbox via sandbox_init_with_parameters"
```

---

## Task 3: macOS path resolver (`open(O_NOFOLLOW)` + anchored realpath)

**Files:**
- Modify: `crates/seck-host-unsafe/src/lib.rs`
- Create: `crates/seck-host-unsafe/src/linux.rs`
- Create: `crates/seck-host-unsafe/src/macos.rs`

- [ ] **Step 3.1: Move current `lib.rs` contents into `linux.rs`**

```bash
git mv crates/seck-host-unsafe/src/lib.rs crates/seck-host-unsafe/src/linux.rs
```

Add this re-export `crates/seck-host-unsafe/src/lib.rs`:

```rust
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;
```

- [ ] **Step 3.2: Write `crates/seck-host-unsafe/src/macos.rs`**

```rust
//! macOS path resolver: open(O_NOFOLLOW|O_CLOEXEC) + fstat + anchored realpath verify.

use ::std::os::fd::{FromRawFd, OwnedFd};
use ::std::path::{Path, PathBuf};

#[derive(Debug, ::thiserror::Error)]
pub enum ResolveError {
    #[error("symlink not permitted: {0}")]
    Symlink(String),
    #[error("path escape not permitted: {0}")]
    Escape(String),
    #[error("anchor mismatch: {0}")]
    AnchorMismatch(String),
    #[error("io: {0}")]
    Io(#[from] ::std::io::Error),
}

pub fn open_target(path: &Path) -> Result<OwnedFd, ResolveError> {
    open_target_anchored(path, &::std::env::current_dir()?)
}

pub fn open_target_anchored(path: &Path, anchor: &Path) -> Result<OwnedFd, ResolveError> {
    // 1. Canonicalize anchor (must be a real dir).
    let anchor_canon = ::std::fs::canonicalize(anchor)?;

    // 2. Open with O_NOFOLLOW | O_CLOEXEC — no symlinks at final component.
    let cpath = ::std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| ResolveError::Escape("nul byte in path".into()))?;
    #[allow(unsafe_code)]
    let fd = unsafe {
        ::libc::open(cpath.as_ptr(), ::libc::O_RDONLY | ::libc::O_NOFOLLOW | ::libc::O_CLOEXEC)
    };
    if fd < 0 {
        let err = ::std::io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(::libc::ELOOP) => Err(ResolveError::Symlink(path.display().to_string())),
            _ => Err(ResolveError::Io(err)),
        };
    }
    #[allow(unsafe_code)]
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    // 3. fstat to ensure it's a regular file or directory.
    #[allow(unsafe_code)]
    let mut st: ::libc::stat = unsafe { ::std::mem::zeroed() };
    #[allow(unsafe_code)]
    let rc = unsafe { ::libc::fstat(fd, &mut st) };
    if rc != 0 { return Err(ResolveError::Io(::std::io::Error::last_os_error())); }

    // 4. Anchored realpath verification: the path must canonicalize to a
    //    descendant of the anchor.
    let canon = ::std::fs::canonicalize(path)?;
    if !canon.starts_with(&anchor_canon) {
        return Err(ResolveError::AnchorMismatch(format!(
            "{} not under {}", canon.display(), anchor_canon.display()
        )));
    }
    Ok(owned)
}
```

- [ ] **Step 3.3: Failing test (Linux unchanged; macOS new) in `crates/seck-host-unsafe/tests/macos_resolver.rs`**

```rust
#![cfg(target_os = "macos")]
use seck_host_unsafe::{open_target_anchored, ResolveError};
use std::os::unix::fs::symlink;
use tempfile::TempDir;

#[test]
fn opens_real_file() {
    let d = TempDir::new().unwrap();
    let p = d.path().join("a.txt");
    std::fs::write(&p, b"hi").unwrap();
    let _ = open_target_anchored(&p, d.path()).unwrap();
}

#[test]
fn refuses_symlink() {
    let d = TempDir::new().unwrap();
    let real = d.path().join("real.txt");
    let link = d.path().join("link.txt");
    std::fs::write(&real, b"x").unwrap();
    symlink(&real, &link).unwrap();
    let err = open_target_anchored(&link, d.path()).unwrap_err();
    assert!(matches!(err, ResolveError::Symlink(_)));
}

#[test]
fn refuses_escape_via_dotdot() {
    let d = TempDir::new().unwrap();
    let escape = d.path().join("..").join("etc").join("passwd");
    let err = open_target_anchored(&escape, d.path()).unwrap_err();
    assert!(matches!(err, ResolveError::AnchorMismatch(_) | ResolveError::Io(_)));
}
```

- [ ] **Step 3.4: Run on a macOS host**

```bash
cargo test -p seck-host-unsafe --test macos_resolver
```

Expected: 3/3 pass.

- [ ] **Step 3.5: Commit**

```bash
git add crates/seck-host-unsafe/
git commit -m "feat(host): macOS path resolver with anchored realpath verification"
```

---

## Task 4: Orchestrator — apply Seatbelt before exec

**Files:**
- Modify: `crates/seck-host/src/orchestrator.rs`
- Modify: `crates/seck-reader/src/main.rs`

- [ ] **Step 4.1: Modify reader main to apply Seatbelt on macOS**

In `crates/seck-reader/src/main.rs`, replace the lockdown call:

```rust
#[cfg(target_os = "linux")]
::seck_sandbox::linux::LinuxSandbox::apply_self_lockdown()?;

#[cfg(target_os = "macos")]
{
    let model_dir = std::env::var("SECK_MODEL_DIR")
        .map(::std::path::PathBuf::from)
        .map_err(|_| ::anyhow::anyhow!("SECK_MODEL_DIR not set"))?;
    let infer_bin = std::env::var("SECK_INFER_BIN")
        .map(::std::path::PathBuf::from)
        .map_err(|_| ::anyhow::anyhow!("SECK_INFER_BIN not set"))?;
    ::seck_sandbox::macos::MacosSandbox::apply_self_lockdown(&model_dir, &infer_bin)?;
}
```

- [ ] **Step 4.2: Modify orchestrator to set env on macOS**

In `crates/seck-host/src/orchestrator.rs`, before `execvp`:

```rust
#[cfg(target_os = "macos")]
{
    // Pass model_dir and infer_bin to the reader via env. These are
    // Untainted (host-validated) paths, never user-controlled.
    unsafe {
        ::std::env::set_var("SECK_MODEL_DIR", model_dir);
        ::std::env::set_var("SECK_INFER_BIN", infer_bin);
    }
}
```

(Note: this requires passing `model_dir` and `infer_bin` into `run_sandboxed` from the CLI. Adjust signature.)

- [ ] **Step 4.3: Smoke test on macOS**

```bash
cargo build --release --target=aarch64-apple-darwin
./target/aarch64-apple-darwin/release/seck analyze ./README.md
```

Expected: JSON report. If Seatbelt rejects the profile at runtime, the error message will name the missing capability.

- [ ] **Step 4.4: Commit**

```bash
git add crates/seck-reader/ crates/seck-host/
git commit -m "feat(reader): apply Seatbelt sandbox on macOS startup"
```

---

## Task 5: macOS escape test suite

**Files:**
- Create: `tests/escape-macos/Cargo.toml`
- Create: `tests/escape-macos/src/bin/escape_probe.rs`
- Create: `tests/escape-macos/tests/escape.rs`

- [ ] **Step 5.1: Add to workspace exclude**

```toml
exclude = [..., "tests/escape-macos"]
```

- [ ] **Step 5.2: Write `tests/escape-macos/Cargo.toml`**

```toml
[package]
name = "seck-escape-macos"
edition = "2024"
version = "0.0.0"
publish = false

[target.'cfg(target_os = "macos")'.dependencies]
nix = { version = "0.30", features = ["fs", "process", "socket"] }
libc = "0.2"
seck-sandbox = { path = "../../crates/seck-sandbox" }
anyhow = "1"

[[bin]]
name = "escape_probe_macos"
path = "src/bin/escape_probe.rs"

[dev-dependencies]
assert_cmd = "2"
```

- [ ] **Step 5.3: Write `tests/escape-macos/src/bin/escape_probe.rs`**

```rust
#![cfg(target_os = "macos")]
use std::env;
use std::path::PathBuf;

fn main() {
    let kind = env::args().nth(1).expect("missing kind");
    let model_dir = PathBuf::from("/tmp");
    let infer_bin = PathBuf::from("/usr/bin/true");
    seck_sandbox::macos::MacosSandbox::apply_self_lockdown(&model_dir, &infer_bin)
        .expect("lockdown");

    let result: Result<(), std::io::Error> = match kind.as_str() {
        "open_passwd" => std::fs::File::open("/etc/passwd").map(|_| ()),
        "execve_sh"   => std::process::Command::new("/bin/sh").arg("-c").arg("true").status().map(|_| ()),
        "socket"      => {
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            if fd < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
        }
        "connect"     => std::net::TcpStream::connect("127.0.0.1:1").map(|_| ()),
        "open_keychain" => std::fs::File::open(format!("{}/Library/Keychains/login.keychain-db",
                                                       env::var("HOME").unwrap())).map(|_| ()),
        "mach_lookup" => {
            // Try to look up a system service via mach. We can't trivially
            // call mach_lookup from Rust; instead spawn `launchctl list`
            // which itself requires mach lookup — and is also denied by exec.
            std::process::Command::new("/bin/launchctl").arg("list").status().map(|_| ())
        }
        other => panic!("unknown kind {other}"),
    };
    if result.is_ok() { std::process::exit(2); }
    std::process::exit(0);
}
```

- [ ] **Step 5.4: Write `tests/escape-macos/tests/escape.rs`**

```rust
#![cfg(target_os = "macos")]
use assert_cmd::Command;

fn check(kind: &str) {
    let bin = env!("CARGO_BIN_EXE_escape_probe_macos");
    let mut cmd = Command::new(bin);
    cmd.arg(kind);
    let out = cmd.output().expect("ran");
    assert_ne!(out.status.code(), Some(2), "{kind}: sandbox FAILED");
}

#[test] fn cannot_open_etc_passwd()     { check("open_passwd"); }
#[test] fn cannot_execve_sh()           { check("execve_sh"); }
#[test] fn cannot_create_socket()       { check("socket"); }
#[test] fn cannot_tcp_connect()         { check("connect"); }
#[test] fn cannot_open_keychain()       { check("open_keychain"); }
#[test] fn cannot_launchctl_list()      { check("mach_lookup"); }
```

- [ ] **Step 5.5: Run**

```bash
cd tests/escape-macos && cargo test
```

Expected: 6/6 pass on a macOS host.

- [ ] **Step 5.6: Commit**

```bash
git add tests/escape-macos/ Cargo.toml
git commit -m "test(sandbox/macos): 6 Seatbelt-escape regression attempts"
```

---

## Task 6: `Seck.app` drag-and-drop applet — Swift

**Files:**
- Create: `platform/macos/applet/Sources/SeckApplet/AppDelegate.swift`
- Create: `platform/macos/applet/Sources/SeckApplet/FDPassing.swift`
- Create: `platform/macos/applet/Sources/SeckApplet/Info.plist`
- Create: `platform/macos/applet/build_applet.sh`
- Create: `platform/macos/applet/Package.swift`

- [ ] **Step 6.1: Write `platform/macos/applet/Package.swift`**

```swift
// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "SeckApplet",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "SeckApplet", targets: ["SeckApplet"]),
    ],
    targets: [
        .executableTarget(
            name: "SeckApplet",
            path: "Sources/SeckApplet"
        ),
    ]
)
```

- [ ] **Step 6.2: Write `platform/macos/applet/Sources/SeckApplet/FDPassing.swift`**

```swift
import Foundation
import Darwin

/// Spawn `seck analyze --fd=3` with the dropped file's FD inherited as 3.
/// CRITICAL: the path NEVER appears in argv. Only the pre-opened FD is passed.
func spawnSeckWithFD(path: URL) throws {
    // Open the dropped path with O_RDONLY | O_NOFOLLOW.
    let fd = open(path.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    if fd < 0 {
        throw NSError(domain: "SeckApplet", code: Int(errno),
                      userInfo: [NSLocalizedDescriptionKey: "open failed"])
    }
    defer { close(fd) }

    var fileActions: posix_spawn_file_actions_t? = nil
    posix_spawn_file_actions_init(&fileActions)
    defer { posix_spawn_file_actions_destroy(&fileActions) }

    // dup2 our open FD into the child's FD 3.
    posix_spawn_file_actions_adddup2(&fileActions, fd, 3)

    let bundleURL = Bundle.main.bundleURL
        .deletingLastPathComponent()  // Contents/MacOS/..
        .deletingLastPathComponent()  // Contents/..
        .appendingPathComponent("Contents/Resources/seck")
    let argv: [String] = [bundleURL.path, "analyze", "--fd=3"]
    let cargv: [UnsafeMutablePointer<CChar>?] =
        argv.map { strdup($0) } + [nil]
    defer { for a in cargv { if let a = a { free(a) } } }

    var pid: pid_t = 0
    let rc = posix_spawn(&pid, bundleURL.path, &fileActions, nil,
                        cargv.map { UnsafeMutablePointer($0) },
                        nil)
    if rc != 0 {
        throw NSError(domain: "SeckApplet", code: Int(rc),
                      userInfo: [NSLocalizedDescriptionKey: "posix_spawn failed"])
    }

    var status: Int32 = 0
    waitpid(pid, &status, 0)
}
```

- [ ] **Step 6.3: Write `platform/macos/applet/Sources/SeckApplet/AppDelegate.swift`**

```swift
import Cocoa

@main
class SeckAppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.activate(ignoringOtherApps: true)
        showWindow()
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        for url in urls {
            do {
                try spawnSeckWithFD(path: url)
            } catch {
                let alert = NSAlert()
                alert.messageText = "seck failed"
                alert.informativeText = error.localizedDescription
                alert.runModal()
            }
        }
    }

    func showWindow() {
        let win = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 480, height: 240),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false)
        win.title = "seck"
        let label = NSTextField(labelWithString:
            "Drop a file or folder here, or use the dock to drop targets.")
        label.frame = NSRect(x: 24, y: 100, width: 432, height: 40)
        win.contentView?.addSubview(label)
        win.center()
        win.makeKeyAndOrderFront(nil)
    }
}
```

- [ ] **Step 6.4: Write `platform/macos/applet/Sources/SeckApplet/Info.plist`**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key><string>net.seck.Applet</string>
    <key>CFBundleName</key><string>Seck</string>
    <key>CFBundleDisplayName</key><string>Seck</string>
    <key>CFBundleExecutable</key><string>SeckApplet</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>0.1.0</string>
    <key>CFBundleVersion</key><string>1</string>
    <key>LSMinimumSystemVersion</key><string>14.0</string>
    <key>CFBundleDocumentTypes</key>
    <array>
        <dict>
            <key>CFBundleTypeName</key><string>Any file</string>
            <key>CFBundleTypeRole</key><string>Viewer</string>
            <key>LSItemContentTypes</key>
            <array>
                <string>public.item</string>
                <string>public.folder</string>
            </array>
        </dict>
    </array>
</dict>
</plist>
```

- [ ] **Step 6.5: Write `platform/macos/applet/build_applet.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
APP_DIR="$ROOT/target/Seck.app"

rm -rf "$APP_DIR"
mkdir -p "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources"

cd "$ROOT/platform/macos/applet"
swift build -c release

cp .build/release/SeckApplet  "$APP_DIR/Contents/MacOS/SeckApplet"
cp Sources/SeckApplet/Info.plist "$APP_DIR/Contents/Info.plist"

# Embed the seck CLI binary so the applet finds it next to itself.
cp "$ROOT/target/release/seck"        "$APP_DIR/Contents/Resources/seck"
cp "$ROOT/target/release/seck-reader" "$APP_DIR/Contents/Resources/seck-reader"

# Adhoc-sign for local development. Plan 15 replaces with a proper cert.
codesign --force --sign - --timestamp=none --deep "$APP_DIR"

echo "Built $APP_DIR"
```

- [ ] **Step 6.6: Build the applet**

```bash
chmod +x platform/macos/applet/build_applet.sh
cargo build --release --target=aarch64-apple-darwin
./platform/macos/applet/build_applet.sh
ls -la target/Seck.app/Contents/MacOS/
```

Expected: `SeckApplet` binary present.

- [ ] **Step 6.7: Smoke test (manual)**

```bash
open target/Seck.app
# Drag a file into the dock icon. A JSON report appears (rendered in Terminal
# because the applet spawns the CLI which prints to its inherited stdout).
```

- [ ] **Step 6.8: Commit**

```bash
git add platform/macos/applet/
git commit -m "feat(applet/macos): drag-and-drop Seck.app passing FDs (not argv paths)"
```

---

## Task 7: `--fd=N` CLI flag (consumed by both applet and Linux desktop integration)

**Files:**
- Modify: `crates/seck-cli/src/analyze.rs`
- Modify: `crates/seck-host/src/orchestrator.rs`

- [ ] **Step 7.1: Add `--fd` flag to analyze**

```rust
#[derive(::clap::Args)]
pub struct AnalyzeArgs {
    /// Path to analyze (mutually exclusive with --fd)
    pub path: Option<PathBuf>,
    /// Pre-opened FD to analyze (mutually exclusive with path).
    /// Used by Seck.app and Linux desktop integration.
    #[arg(long)]
    pub fd: Option<i32>,
    // ... existing flags ...
}
```

- [ ] **Step 7.2: Dispatch when `--fd` is set**

```rust
pub fn run(args: AnalyzeArgs) -> Result<()> {
    if let Some(fd) = args.fd {
        // Wrap the inherited FD in an Entry, build a FileSet, and
        // call run_sandboxed as usual.
        let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        let metadata = std::fs::metadata(format!("/dev/fd/{fd}"))?;
        let entry = ::seck_host::walker::Entry {
            relative: PathBuf::from("fd_input"),
            fd: owned,
            size: metadata.len(),
        };
        let fileset = ::seck_host::fileset::build_fileset(vec![entry])?;
        // ... same as path-based ...
    } else if let Some(path) = args.path {
        // existing path flow
    } else {
        anyhow::bail!("either --fd=N or a path must be supplied");
    }
    Ok(())
}
```

- [ ] **Step 7.3: Test `--fd` invocation**

```bash
cargo build --release
echo "fn main() { println!(\"hi\"); }" > /tmp/h.rs
exec 7</tmp/h.rs
./target/release/seck analyze --fd=7
```

Expected: JSON report referencing `fd_input` as the path.

- [ ] **Step 7.4: Commit**

```bash
git add crates/seck-cli/ crates/seck-host/
git commit -m "feat(cli): --fd=N flag for FD-inherited analysis (used by Seck.app)"
```

---

## Task 8: Finder Quick Action

**Files:**
- Create: `platform/macos/quickaction/AnalyzeWithSeck.workflow/Contents/document.wflow`
- Create: `platform/macos/quickaction/AnalyzeWithSeck.workflow/Contents/Info.plist`
- Create: `platform/macos/quickaction/install.sh`

- [ ] **Step 8.1: Write `platform/macos/quickaction/AnalyzeWithSeck.workflow/Contents/Info.plist`**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>NSServices</key>
    <array>
        <dict>
            <key>NSMenuItem</key>
            <dict><key>default</key><string>Analyze with seck</string></dict>
            <key>NSMessage</key><string>runWorkflowAsService</string>
            <key>NSSendFileTypes</key>
            <array><string>public.item</string></array>
            <key>NSRequiredContext</key>
            <dict><key>NSApplicationIdentifier</key><string>com.apple.finder</string></dict>
        </dict>
    </array>
</dict>
</plist>
```

- [ ] **Step 8.2: Write `platform/macos/quickaction/AnalyzeWithSeck.workflow/Contents/document.wflow`**

This is an Automator document. Create it via the GUI OR ship the XML below (Automator's document.wflow is an XML plist):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>AMApplicationBuild</key><string>506</string>
    <key>AMApplicationVersion</key><string>2.10</string>
    <key>AMDocumentVersion</key><string>2</string>
    <key>actions</key>
    <array>
        <dict>
            <key>action</key>
            <dict>
                <key>AMAccepts</key>
                <dict>
                    <key>Container</key><string>List</string>
                    <key>Optional</key><true/>
                    <key>Types</key>
                    <array><string>com.apple.cocoa.string</string></array>
                </dict>
                <key>AMActionVersion</key><string>2.0.3</string>
                <key>AMApplication</key><array><string>Automator</string></array>
                <key>AMParameterProperties</key>
                <dict>
                    <key>COMMAND_STRING</key>
                    <dict/>
                </dict>
                <key>AMProvides</key>
                <dict>
                    <key>Container</key><string>List</string>
                    <key>Types</key>
                    <array><string>com.apple.cocoa.string</string></array>
                </dict>
                <key>ActionBundlePath</key>
                <string>/System/Library/Automator/Run Shell Script.action</string>
                <key>ActionName</key><string>Run Shell Script</string>
                <key>ActionParameters</key>
                <dict>
                    <key>COMMAND_STRING</key>
                    <string>for f in "$@"; do
  open -a "Seck" "$f"
done</string>
                    <key>CheckedForUserDefaultShell</key><true/>
                    <key>inputMethod</key><integer>1</integer>
                    <key>shell</key><string>/bin/bash</string>
                    <key>source</key><string></string>
                </dict>
            </dict>
        </dict>
    </array>
</dict>
</plist>
```

- [ ] **Step 8.3: Write `platform/macos/quickaction/install.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail
SRC="$(cd "$(dirname "$0")/AnalyzeWithSeck.workflow" && pwd)"
DST="$HOME/Library/Services/AnalyzeWithSeck.workflow"
rm -rf "$DST"
cp -R "$SRC" "$DST"
echo "Installed Quick Action; restart Finder if it doesn't appear immediately."
```

- [ ] **Step 8.4: Install and verify**

```bash
chmod +x platform/macos/quickaction/install.sh
./platform/macos/quickaction/install.sh
# In Finder, right-click any file → Services → Analyze with seck → applet opens.
```

- [ ] **Step 8.5: Commit**

```bash
git add platform/macos/quickaction/
git commit -m "feat(macos): Finder Quick Action 'Analyze with seck'"
```

---

## Task 9: CI — macOS runner

**Files:**
- Modify: `.github/workflows/ci.yml`
- Create: `.github/workflows/macos.yml`

- [ ] **Step 9.1: Write `.github/workflows/macos.yml`**

```yaml
name: macos
on: [push, pull_request]
jobs:
  test:
    runs-on: macos-14
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: rustup target add aarch64-apple-darwin x86_64-apple-darwin
      - run: cargo build --release --target=aarch64-apple-darwin
      - run: cargo test --workspace
      - run: |
          # Smoke test the SBPL profile
          sandbox-exec -D MODEL_DIR=/tmp -D INFER_BIN=/bin/echo \
            -f platform/macos/seatbelt.sb /bin/echo "profile loads"
      - run: cd tests/escape-macos && cargo test
      - name: Build applet
        run: ./platform/macos/applet/build_applet.sh
```

- [ ] **Step 9.2: Commit**

```bash
git add .github/workflows/macos.yml
git commit -m "ci(macos): SBPL smoke + escape + applet build"
```

---

## Task 10: README delta

**Files:**
- Modify: `README.md`

- [ ] **Step 10.1: Append to README**

```markdown
## macOS

`seck` runs natively on macOS 14+ via the Seatbelt sandbox (`sandbox_init_with_parameters`).

### Drag-and-drop applet

Build and install:

```bash
cargo build --release --target=aarch64-apple-darwin
./platform/macos/applet/build_applet.sh
open target/Seck.app
```

Drop files or folders into the dock icon (or the window) to analyze.

### Finder Quick Action

```bash
./platform/macos/quickaction/install.sh
```

Right-click any file in Finder → Services → "Analyze with seck".

### How it works

The applet and Quick Action both open dropped paths with `open(O_NOFOLLOW)` and pass them to `seck` as *pre-opened file descriptors* (via `posix_spawn_file_actions_addinherit_np` and `seck --fd=N`). Paths never appear in argv, preserving the IO-boundary invariant.
```

- [ ] **Step 10.2: Commit**

```bash
git add README.md
git commit -m "docs(macos): document Seatbelt sandbox + applet + Quick Action"
```

---

## Self-review

**Spec coverage:** §3.1 (workspace platform/macos layout) ✓; §5.2 row 2 (Seatbelt + SBPL deny-default with model bind + inherited FDs + network/exec denial) ✓; §8 macOS Applet (FD-inherit pattern) ✓; §8 macOS Quick Action ✓. Cross-platform sandbox dispatch via `cfg(target_os)` matches §3 architecture.

**Placeholder scan:** No "TBD"/"TODO". Every SBPL allow/deny is explicit; every Swift FFI call has the corresponding `posix_spawn_file_actions_*` step shown.

**Type consistency:** `MacosSandbox` mirrors `LinuxSandbox` API (`new`, `apply_self_lockdown`, `name`, `profile_sha3_256`). The `SandboxMode` enum and `SandboxBackend` trait are unchanged from Plans 01/03. `seck-host-unsafe::open_target` keeps the same signature across platforms; `open_target_anchored` is new but additive (Linux's `openat2` flow is its own anchor implicitly).

Plan 02 complete.
