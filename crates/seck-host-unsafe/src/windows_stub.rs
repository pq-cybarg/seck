//! Windows stub. seck-host's walker / orchestrator path that consumes
//! `open_target` is cfg(unix)-only, so this stub is never called at
//! runtime — it exists only so `cargo check --workspace` succeeds on
//! Windows. The Windows analogue is the HANDLE-handoff path in
//! `seck-host::orchestrator_windows`.

use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("seck-host-unsafe::open_target is Unix-only; Windows uses HANDLE-handoff in seck-host::orchestrator_windows")]
    UnsupportedPlatform,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Always fails on Windows. The Unix analogue returns an `OwnedFd`;
/// returning `Result<(), ResolveError>` here intentionally has a
/// different type so accidental cross-platform use is a hard error.
pub fn open_target(_path: &Path) -> Result<(), ResolveError> {
    Err(ResolveError::UnsupportedPlatform)
}
