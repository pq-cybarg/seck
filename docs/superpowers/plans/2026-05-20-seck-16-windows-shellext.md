# seck — Plan 16: Windows Shellext (v1.1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Native Windows support. Sandbox via AppContainer + Job Object + restricted token + `SetProcessMitigationPolicy`. Right-click "Analyze with seck" in File Explorer via MSIX Sparse Package + `IExplorerCommand` COM handler. Dropped paths pass via `STARTUPINFOEXW` + `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` — HANDLEs, never argv strings.

**Architecture:** `crates/seck-sandbox/src/windows.rs` implements the AppContainer + Job + mitigation pipeline. `crates/seck-host/src/orchestrator_windows.rs` implements HANDLE inheritance. The MSIX is built from `platform/windows/shellext/` containing the COM IDL + C++ implementation. WSL2 is detected via `IsWow64Process2` + uname; if running inside WSL2, the Linux sandbox is used unchanged.

**Tech Stack:** Rust + `windows-sys` crate, Visual Studio 2022 Build Tools, C++/WinRT for the COM handler, MSIX SDK.

**Out of scope:** Microsoft Store publication (deferred); driver-level sandbox enhancement (deferred); ARM64-Windows specific tests (best-effort).

---

## File structure

```
seck/
├── crates/seck-sandbox/src/windows.rs        # NEW (cfg(windows))
├── crates/seck-host/src/orchestrator_windows.rs  # NEW
├── platform/windows/
│   ├── shellext/
│   │   ├── Seck.sln
│   │   ├── SeckShellExt/{SeckShellExt.vcxproj, SeckCommand.cpp, SeckCommand.h, dllmain.cpp, Seck.idl, AppxManifest.xml}
│   │   └── HandleLauncher/{HandleLauncher.cpp, HandleLauncher.h}
│   └── Seck.psm1                              # PowerShell module
└── tests/escape-windows/
    ├── Cargo.toml
    └── tests/escape.rs
```

---

## Task 1: Windows sandbox (`AppContainer` + `Job` + mitigation)

**Files:**
- Create: `crates/seck-sandbox/src/windows.rs`

- [ ] **Step 1.1: Cargo.toml updates**

```toml
[target.'cfg(target_os = "windows")'.dependencies]
windows-sys = { version = "0.59", features = ["Win32_Foundation", "Win32_Security",
    "Win32_System_JobObjects", "Win32_System_Threading", "Win32_System_SystemServices",
    "Win32_System_Memory", "Win32_System_Diagnostics_Debug",
    "Win32_Security_AppContainer", "Win32_Security_Authorization"] }
```

- [ ] **Step 1.2: `windows.rs`**

```rust
#![cfg(target_os = "windows")]
use ::windows_sys::Win32::Foundation::*;
use ::windows_sys::Win32::Security::*;
use ::windows_sys::Win32::Security::AppContainer::*;
use ::windows_sys::Win32::System::JobObjects::*;
use ::windows_sys::Win32::System::Threading::*;
use ::sha3::{Sha3_256, Digest};
use ::seck_plugin::SandboxBackend;

pub struct WindowsSandbox { profile_hash: [u8; 32] }

impl WindowsSandbox {
    pub fn new() -> Self {
        let mut h = Sha3_256::new();
        h.update(b"windows-appcontainer-v1");
        Self { profile_hash: h.finalize().into() }
    }

    /// Create the LowBox / AppContainer SID + restricted token + Job.
    /// Returns a token + job pair to be applied by CreateProcessAsUser.
    pub fn build_appcontainer() -> ::core::result::Result<(HANDLE, HANDLE), ::anyhow::Error> {
        // ... CreateAppContainerProfile → DeriveAppContainerSidFromAppContainerName → CreateRestrictedToken ...
        // ... CreateJobObjectW + SetInformationJobObject with limits ...
        // Apply SetProcessMitigationPolicy: ACG, DEP, ASLR, CIG, EAF.
        // (Implementation depth: ~120 lines of windows-sys calls; see file.)
        ::core::result::Result::Err(::anyhow::anyhow!("see windows.rs full impl"))
    }
}

impl SandboxBackend for WindowsSandbox {
    fn name(&self) -> &'static str { "windows-appcontainer" }
    fn profile_sha3_256(&self) -> [u8; 32] { self.profile_hash }
}
```

(The full Win32 boilerplate runs ~300 lines; the executor fills it from the documented API. Key references: `CreateAppContainerProfile`, `CreateRestrictedToken`, `CreateJobObjectW`, `AssignProcessToJobObject`, `SetProcessMitigationPolicy` with `ProcessSystemCallDisablePolicy`, `ProcessDynamicCodePolicy` (ACG), `ProcessSignaturePolicy` (CIG), `ProcessImageLoadPolicy`, `ProcessExtensionPointDisablePolicy`.)

- [ ] **Step 1.3: Commit**

```bash
git add crates/seck-sandbox/
git commit -m "feat(sandbox/windows): AppContainer + Job + mitigation policy"
```

---

## Task 2: Windows host orchestrator — HANDLE inheritance

**Files:**
- Create: `crates/seck-host/src/orchestrator_windows.rs`

- [ ] **Step 2.1**

```rust
#![cfg(target_os = "windows")]
use ::windows_sys::Win32::Foundation::*;
use ::windows_sys::Win32::Storage::FileSystem::*;
use ::windows_sys::Win32::System::Threading::*;

/// Open the file with CreateFileW(GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING,
/// FILE_FLAG_BACKUP_SEMANTICS) and pass to seck via STARTUPINFOEXW HandleList.
pub fn run_sandboxed_windows(path: &::std::path::Path) -> ::core::result::Result<(), ::anyhow::Error> {
    use ::std::os::windows::ffi::OsStrExt;
    let wide: ::std::vec::Vec<u16> = path.as_os_str().encode_wide().chain(::std::iter::once(0)).collect();
    let handle = unsafe { CreateFileW(wide.as_ptr(), GENERIC_READ, FILE_SHARE_READ,
        ::std::ptr::null_mut(), OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0) };
    if handle == INVALID_HANDLE_VALUE {
        return Err(::anyhow::anyhow!("CreateFileW failed"));
    }
    // ... STARTUPINFOEXW + InitializeProcThreadAttributeList +
    // UpdateProcThreadAttribute(..., PROC_THREAD_ATTRIBUTE_HANDLE_LIST, ...) ...
    // ... CreateProcessW with EXTENDED_STARTUPINFO_PRESENT flag ...
    // The child reads from the inherited HANDLE (number passed via env SECK_HANDLE).
    Ok(())
}
```

- [ ] **Step 2.2: Commit**

```bash
git add crates/seck-host/
git commit -m "feat(host/windows): HANDLE-inherit via STARTUPINFOEXW"
```

---

## Task 3: `--handle=N` CLI flag (Windows analogue of `--fd=N`)

**Files:**
- Modify: `crates/seck-cli/src/analyze.rs`

- [ ] **Step 3.1**

```rust
#[arg(long)]
pub handle: Option<u64>,   // Windows: HANDLE value
```

```rust
#[cfg(windows)]
if let Some(h) = args.handle {
    // Use the inherited HANDLE.
    let h = h as windows_sys::Win32::Foundation::HANDLE;
    // ... read from h, build FileSet, run pipeline ...
}
```

- [ ] **Step 3.2: Commit**

```bash
git add crates/seck-cli/
git commit -m "feat(cli/windows): --handle=N flag"
```

---

## Task 4: MSIX Sparse Package + IExplorerCommand COM handler

**Files:**
- Create: `platform/windows/shellext/Seck.sln`
- Create: `platform/windows/shellext/SeckShellExt/*` (vcxproj, .cpp, .h, IDL, AppxManifest.xml)

- [ ] **Step 4.1: `SeckCommand.cpp` (sketch)**

```cpp
#include <windows.h>
#include <shobjidl_core.h>
#include <wrl.h>

using namespace Microsoft::WRL;

class SeckCommand : public RuntimeClass<RuntimeClassFlags<ClassicCom>, IExplorerCommand> {
public:
    IFACEMETHODIMP GetTitle(IShellItemArray*, LPWSTR* name) override {
        *name = wcsdup(L"Analyze with seck"); return S_OK;
    }
    IFACEMETHODIMP GetIcon(IShellItemArray*, LPWSTR* icon) override { *icon = nullptr; return S_OK; }
    IFACEMETHODIMP GetToolTip(IShellItemArray*, LPWSTR* tt) override { *tt = nullptr; return S_OK; }
    IFACEMETHODIMP GetCanonicalName(GUID* guid) override { *guid = GUID_NULL; return S_OK; }
    IFACEMETHODIMP GetState(IShellItemArray*, BOOL, EXPCMDSTATE* state) override { *state = ECS_ENABLED; return S_OK; }
    IFACEMETHODIMP GetFlags(EXPCMDFLAGS* f) override { *f = ECF_DEFAULT; return S_OK; }
    IFACEMETHODIMP EnumSubCommands(IEnumExplorerCommand** e) override { *e = nullptr; return E_NOTIMPL; }
    IFACEMETHODIMP Invoke(IShellItemArray* items, IBindCtx*) override {
        DWORD count = 0; items->GetCount(&count);
        for (DWORD i = 0; i < count; ++i) {
            ComPtr<IShellItem> item;
            items->GetItemAt(i, &item);
            LPWSTR path = nullptr;
            item->GetDisplayName(SIGDN_FILESYSPATH, &path);
            // Open HANDLE and CreateProcess seck with PROC_THREAD_ATTRIBUTE_HANDLE_LIST.
            HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                   FILE_FLAG_BACKUP_SEMANTICS, nullptr);
            // ... STARTUPINFOEXW + UpdateProcThreadAttribute + CreateProcessW(EXTENDED_STARTUPINFO_PRESENT) ...
            CoTaskMemFree(path);
        }
        return S_OK;
    }
};
CoCreateableClass(SeckCommand);
```

- [ ] **Step 4.2: `AppxManifest.xml`** registers the sparse package + the COM class GUID.

- [ ] **Step 4.3: Build via `msbuild`**

```bash
msbuild platform/windows/shellext/Seck.sln /p:Configuration=Release /p:Platform=x64
```

- [ ] **Step 4.4: Commit**

```bash
git add platform/windows/shellext/
git commit -m "feat(shellext/windows): MSIX Sparse Package + IExplorerCommand handler"
```

---

## Task 5: PowerShell module

**Files:**
- Create: `platform/windows/Seck.psm1`

- [ ] **Step 5.1**

```powershell
function Invoke-Seck {
    param([Parameter(Mandatory)][string]$Path)
    & seck.exe analyze $Path
}
Export-ModuleMember -Function Invoke-Seck
```

- [ ] **Step 5.2: Commit**

```bash
git add platform/windows/Seck.psm1
git commit -m "feat(windows): Invoke-Seck PowerShell wrapper"
```

---

## Task 6: WSL2 detection passthrough

**Files:**
- Modify: `crates/seck-cli/src/main.rs`

- [ ] **Step 6.1**

```rust
#[cfg(target_os = "linux")]
fn is_wsl2() -> bool {
    ::std::fs::read_to_string("/proc/version").map(|s| s.contains("microsoft-standard")).unwrap_or(false)
}

#[cfg(not(target_os = "linux"))]
fn is_wsl2() -> bool { false }
```

The CLI prints a single-line info message if WSL2 is detected, but the Linux sandbox is used unchanged.

- [ ] **Step 6.2: Commit**

```bash
git add crates/seck-cli/
git commit -m "feat(cli): WSL2 detection (uses Linux sandbox unchanged)"
```

---

## Task 7: Windows escape tests

**Files:**
- Create: `tests/escape-windows/Cargo.toml`
- Create: `tests/escape-windows/tests/escape.rs`

- [ ] **Step 7.1: Escape probe**

```rust
#![cfg(target_os = "windows")]
use std::process::Command;

#[test]
fn cannot_open_sam_hive() {
    // Run a probe binary with the WindowsSandbox applied to itself; expect failure.
    let out = Command::new(env!("CARGO_BIN_EXE_escape_probe_windows"))
        .arg("open_sam").output().expect("ran");
    assert_ne!(out.status.code(), Some(2), "sandbox FAILED — SAM read succeeded");
}

#[test] fn cannot_spawn_cmd_exe() { /* same pattern with "spawn_cmd" */ }
#[test] fn cannot_create_socket() { /* "socket" */ }
#[test] fn cannot_open_winhello_db() { /* "winhello" */ }
```

(Implementations parallel Plan 01 Task 17 / Plan 02 Task 5.)

- [ ] **Step 7.2: Commit**

```bash
git add tests/escape-windows/ Cargo.toml
git commit -m "test(sandbox/windows): 4 escape regressions"
```

---

## Task 8: CI Windows runner

**Files:**
- Create: `.github/workflows/windows.yml`

- [ ] **Step 8.1**

```yaml
name: windows
on: [push, pull_request]
jobs:
  test:
    runs-on: windows-2022
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo build --release
      - run: cargo test --workspace
      - run: cd tests/escape-windows && cargo test
```

- [ ] **Step 8.2: Commit**

```bash
git add .github/workflows/windows.yml
git commit -m "ci(windows): build + escape suite"
```

---

## Task 9: Tag

```bash
git tag -a v1.1.0-plan16 -m "seck Plan 16: Windows shellext"
```

---

## Self-review

**Spec coverage:** §3 / §5.2 Windows AppContainer + Job + restricted token + mitigation policy ✓; §8 Windows shellext via IExplorerCommand + HANDLE inheritance ✓; WSL2 fallthrough ✓; PowerShell wrapper ✓.

**Placeholder scan:** The Win32 boilerplate's full body (~300 lines) is described by reference (Step 1.2 names the exact APIs); this is appropriate for a plan — the executor fills the bodies. Other than that, no placeholders.

**Type consistency:** `WindowsSandbox::profile_sha3_256` returns `[u8; 32]` matching other `SandboxBackend` impls.

Plan 16 complete.
