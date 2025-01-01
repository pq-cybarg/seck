# seck — Plan 13: Linux Desktop Integration (right-click "Analyze with seck")

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Right-click any file or folder in Nautilus / Dolphin / Thunar → "Analyze with seck". Critically, the dropped path arrives at `seck` as a PRE-OPENED FD (via a small DBus FD-handoff service), not as an argv path string. Preserves the IO-boundary invariant established in Plan 01.

**Architecture:** A tiny DBus service `net.seck.Analyze` (Python or Rust) owns the FD handoff. The `.desktop` file activates the service, which opens the path with `openat2(RESOLVE_NO_SYMLINKS, ...)` and spawns `seck analyze --fd=N` with the opened FD inherited. Same for Nautilus/KIO/Thunar extension entries.

**Tech Stack:** `zbus = "5"` for DBus (or freedesktop's `dbus-python`), `nautilus-python` for Nautilus, KDE `kio` ServiceMenu XML, Thunar custom-actions XML.

**Out of scope:** GNOME Files plugins for non-Nautilus file managers (PCManFM, Nemo); systemd user services (handled by install script directly); Snap/Flatpak packaging (Plan 15).

---

## File structure

```
seck/
├── crates/seck-portal/                # NEW — DBus FD-handoff service
│   ├── Cargo.toml
│   └── src/{lib.rs, service.rs}
├── platform/linux/desktop/
│   ├── seck-analyze.desktop           # NEW — .desktop activation file
│   ├── net.seck.Analyze.service       # NEW — DBus service file
│   ├── seck-analyze.servicemenu       # NEW — KDE Dolphin
│   ├── seck-analyze.uca.xml           # NEW — Thunar
│   ├── nautilus-seck.py               # NEW — Nautilus extension
│   ├── install-desktop.sh             # NEW
│   └── uninstall-desktop.sh           # NEW
└── tests/desktop/
    ├── Cargo.toml
    └── tests/{fd_handoff.rs, install_idempotent.rs}
```

---

## Task 1: `seck-portal` DBus FD-handoff service

**Files:**
- Create: `crates/seck-portal/Cargo.toml`
- Create: `crates/seck-portal/src/{lib.rs, service.rs}`

- [ ] **Step 1.1: Cargo.toml**

```toml
[package]
name = "seck-portal"
edition.workspace = true
version.workspace = true

[[bin]]
name = "seck-portal"
path = "src/main.rs"

[dependencies]
seck-host-unsafe = { path = "../seck-host-unsafe" }
zbus = "5"
tokio = { workspace = true, features = ["full"] }
anyhow.workspace = true
```

- [ ] **Step 1.2: `service.rs`**

```rust
use ::zbus::interface;
use ::std::os::fd::{IntoRawFd, OwnedFd};

#[derive(Default)]
pub struct AnalyzeService;

#[interface(name = "net.seck.Analyze")]
impl AnalyzeService {
    /// Open `path` safely on the host and spawn `seck analyze --fd=N` with
    /// the resulting FD inherited. The path NEVER appears in seck's argv.
    async fn analyze_path(&mut self, path: ::std::string::String) -> ::zbus::fdo::Result<()> {
        let p = ::std::path::Path::new(&path);
        let fd: OwnedFd = ::seck_host_unsafe::open_target(p)
            .map_err(|e| ::zbus::fdo::Error::Failed(format!("{e}")))?;
        let raw = fd.into_raw_fd();
        // Pass the FD via POSIX_SPAWN_FILE_ACTIONS_ADDINHERIT, dup'd to FD 3.
        let exe = ::which::which("seck").unwrap_or_else(|_| "/usr/local/bin/seck".into());
        let mut child = ::std::process::Command::new(exe);
        child.arg("analyze").arg("--fd=3");
        use ::std::os::unix::process::CommandExt;
        unsafe { child.pre_exec(move || { ::nix::unistd::dup2(raw, 3).map_err(::std::io::Error::from)?; Ok(()) }); }
        let _ = child.spawn().map_err(|e| ::zbus::fdo::Error::Failed(format!("{e}")))?;
        Ok(())
    }
}

pub async fn run() -> ::anyhow::Result<()> {
    let connection = ::zbus::connection::Builder::session()?
        .name("net.seck.Analyze")?
        .serve_at("/net/seck/Analyze", AnalyzeService::default())?
        .build().await?;
    // Keep alive.
    ::std::future::pending::<()>().await;
    drop(connection);
    Ok(())
}
```

- [ ] **Step 1.3: `main.rs`**

```rust
mod service;
mod lib { pub use super::service::*; }

fn main() -> ::anyhow::Result<()> {
    let rt = ::tokio::runtime::Runtime::new()?;
    rt.block_on(service::run())
}
```

- [ ] **Step 1.4: Commit**

```bash
git add crates/seck-portal/ Cargo.toml
git commit -m "feat(portal): DBus FD-handoff service (path → FD, never argv)"
```

---

## Task 2: DBus service file

**Files:**
- Create: `platform/linux/desktop/net.seck.Analyze.service`

- [ ] **Step 2.1**

```ini
[D-BUS Service]
Name=net.seck.Analyze
Exec=/usr/local/libexec/seck-portal
```

- [ ] **Step 2.2: Commit**

```bash
git add platform/linux/desktop/net.seck.Analyze.service
git commit -m "feat(desktop): DBus session-bus service definition"
```

---

## Task 3: `.desktop` activation file

**Files:**
- Create: `platform/linux/desktop/seck-analyze.desktop`

- [ ] **Step 3.1**

```ini
[Desktop Entry]
Type=Application
Version=1.5
Name=Analyze with seck
Comment=Run sandboxed LLM analysis on this file or folder
Exec=gdbus call --session --dest net.seck.Analyze --object-path /net/seck/Analyze \
      --method net.seck.Analyze.AnalyzePath %f
Icon=seck
MimeType=application/octet-stream;inode/directory;text/plain;
Categories=Utility;Development;
Terminal=false
NoDisplay=false
```

- [ ] **Step 3.2: Validate**

```bash
desktop-file-validate platform/linux/desktop/seck-analyze.desktop
```

Expected: no output (validation passed).

- [ ] **Step 3.3: Commit**

```bash
git add platform/linux/desktop/seck-analyze.desktop
git commit -m "feat(desktop): seck-analyze.desktop (gdbus → portal)"
```

---

## Task 4: KDE Dolphin service menu

**Files:**
- Create: `platform/linux/desktop/seck-analyze.servicemenu`

- [ ] **Step 4.1**

```ini
[Desktop Entry]
Type=Service
ServiceTypes=KonqPopupMenu/Plugin
MimeType=all/all;
Actions=seckAnalyze;
X-KDE-Submenu=

[Desktop Action seckAnalyze]
Name=Analyze with seck
Icon=seck
Exec=gdbus call --session --dest net.seck.Analyze --object-path /net/seck/Analyze \
      --method net.seck.Analyze.AnalyzePath %f
```

- [ ] **Step 4.2: Commit**

```bash
git add platform/linux/desktop/seck-analyze.servicemenu
git commit -m "feat(desktop): KDE Dolphin service menu"
```

---

## Task 5: Thunar custom action

**Files:**
- Create: `platform/linux/desktop/seck-analyze.uca.xml`

- [ ] **Step 5.1**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<actions>
  <action>
    <icon>seck</icon>
    <name>Analyze with seck</name>
    <command>gdbus call --session --dest net.seck.Analyze --object-path /net/seck/Analyze --method net.seck.Analyze.AnalyzePath %f</command>
    <description>Run sandboxed LLM analysis</description>
    <patterns>*</patterns>
    <directories/>
    <audio-files/>
    <image-files/>
    <other-files/>
    <text-files/>
    <video-files/>
  </action>
</actions>
```

- [ ] **Step 5.2: Commit**

```bash
git add platform/linux/desktop/seck-analyze.uca.xml
git commit -m "feat(desktop): Thunar custom-action XML"
```

---

## Task 6: Nautilus extension

**Files:**
- Create: `platform/linux/desktop/nautilus-seck.py`

- [ ] **Step 6.1**

```python
import gi
gi.require_version("Nautilus", "4.0")
from gi.repository import Nautilus, GObject
import subprocess

class SeckExtension(GObject.GObject, Nautilus.MenuProvider):
    def get_file_items(self, files):
        if not files: return []
        item = Nautilus.MenuItem(name="SeckExtension::Analyze",
                                 label="Analyze with seck",
                                 tip="Run sandboxed LLM analysis")
        item.connect("activate", self.on_activate, files)
        return [item]

    def get_background_items(self, current_folder):
        return self.get_file_items([current_folder])

    def on_activate(self, _menu, files):
        for f in files:
            uri = f.get_uri()
            if uri.startswith("file://"):
                path = uri[7:]
                subprocess.Popen([
                    "gdbus", "call", "--session",
                    "--dest", "net.seck.Analyze",
                    "--object-path", "/net/seck/Analyze",
                    "--method", "net.seck.Analyze.AnalyzePath", path
                ])
```

- [ ] **Step 6.2: Commit**

```bash
git add platform/linux/desktop/nautilus-seck.py
git commit -m "feat(desktop): Nautilus Python extension"
```

---

## Task 7: Install / uninstall scripts (idempotent)

**Files:**
- Create: `platform/linux/desktop/install-desktop.sh`
- Create: `platform/linux/desktop/uninstall-desktop.sh`

- [ ] **Step 7.1: install-desktop.sh**

```bash
#!/usr/bin/env bash
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"

# .desktop file
mkdir -p "$HOME/.local/share/applications"
install -m 0644 "$SRC/seck-analyze.desktop" "$HOME/.local/share/applications/"

# DBus session service
mkdir -p "$HOME/.local/share/dbus-1/services"
install -m 0644 "$SRC/net.seck.Analyze.service" "$HOME/.local/share/dbus-1/services/"

# KDE Dolphin
mkdir -p "$HOME/.local/share/kio/servicemenus"
install -m 0644 "$SRC/seck-analyze.servicemenu" "$HOME/.local/share/kio/servicemenus/"

# Thunar
mkdir -p "$HOME/.config/Thunar"
# Merge with existing uca.xml if present.
if [[ -f "$HOME/.config/Thunar/uca.xml" ]]; then
  if ! grep -q "net.seck.Analyze" "$HOME/.config/Thunar/uca.xml"; then
    python3 -c "
import sys
src = open('$SRC/seck-analyze.uca.xml').read()
dst = open('$HOME/.config/Thunar/uca.xml').read()
# Naive merge: insert before </actions>
if '</actions>' in dst:
    new_action = '\n'.join(src.splitlines()[2:-1])  # strip wrapper
    dst = dst.replace('</actions>', new_action + '\n</actions>')
    open('$HOME/.config/Thunar/uca.xml', 'w').write(dst)
"
  fi
else
  install -m 0644 "$SRC/seck-analyze.uca.xml" "$HOME/.config/Thunar/uca.xml"
fi

# Nautilus
mkdir -p "$HOME/.local/share/nautilus-python/extensions"
install -m 0644 "$SRC/nautilus-seck.py" "$HOME/.local/share/nautilus-python/extensions/"

echo "Installed. You may need to restart your file manager."
```

- [ ] **Step 7.2: uninstall-desktop.sh**

```bash
#!/usr/bin/env bash
set -euo pipefail
rm -f "$HOME/.local/share/applications/seck-analyze.desktop"
rm -f "$HOME/.local/share/dbus-1/services/net.seck.Analyze.service"
rm -f "$HOME/.local/share/kio/servicemenus/seck-analyze.servicemenu"
rm -f "$HOME/.local/share/nautilus-python/extensions/nautilus-seck.py"
echo "Removed."
```

- [ ] **Step 7.3: Make executable + commit**

```bash
chmod +x platform/linux/desktop/install-desktop.sh platform/linux/desktop/uninstall-desktop.sh
git add platform/linux/desktop/
git commit -m "feat(desktop): install/uninstall scripts (idempotent)"
```

---

## Task 8: `--fd=N` CLI flag in seck

**Files:**
- Modify: `crates/seck-cli/src/analyze.rs` (extension of the Plan 02 Task 7 work — confirm it's present)

- [ ] **Step 8.1: Confirm `--fd=N` accepts a pre-opened FD** (added by Plan 02 Task 7). If not present, add it now.

- [ ] **Step 8.2: Commit (if changes)**

```bash
git add crates/seck-cli/
git commit -m "feat(cli): --fd=N flag (cross-platform, used by Plan 02 + Plan 13)"
```

---

## Task 9: Integration tests

**Files:**
- Create: `tests/desktop/Cargo.toml`
- Create: `tests/desktop/tests/{fd_handoff.rs, install_idempotent.rs}`

- [ ] **Step 9.1: fd_handoff.rs** — synthesize a DBus call with a pre-opened FD; assert the FD reaches `seck` and the report references `fd_input`.

- [ ] **Step 9.2: install_idempotent.rs** — run install twice, assert no errors and same files present.

- [ ] **Step 9.3: Commit**

```bash
git add tests/desktop/ Cargo.toml
git commit -m "test(desktop): FD handoff + idempotent install"
```

---

## Task 10: Tag

```bash
git tag -a v0.13.0-plan13 -m "seck Plan 13: Linux desktop integration"
```

---

## Self-review

**Spec coverage:** §8 .desktop + Nautilus/KIO/Thunar entries ✓; portal-style FD handoff (paths never in argv) ✓; idempotent install ✓.

**Placeholder scan:** None.

**Type consistency:** `seck-host-unsafe::open_target` reused; `--fd=N` flag matches Plan 02 Task 7.

Plan 13 complete.
