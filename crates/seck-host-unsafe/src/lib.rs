//! Safe path resolution. The single crate that holds `unsafe` code in
//! the analysis path. Linux uses `openat2(RESOLVE_NO_SYMLINKS |
//! RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV)`; macOS uses
//! `open(O_NOFOLLOW | O_CLOEXEC)` plus a defensive realpath check. Other
//! platforms get a stub that returns an error.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

// Unix systems that aren't Linux or macOS (BSDs, illumos) get a stub
// that returns an error from `open_target`.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
mod stub;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
pub use stub::*;

// Windows has no FD-handoff path — seck-host's walker is cfg(unix)
// only, so this crate's `open_target` is never called there. We keep
// the crate compilable by exposing a Windows stub that doesn't
// reference `OwnedFd` (which is Unix-only in std).
#[cfg(windows)]
mod windows_stub;
#[cfg(windows)]
pub use windows_stub::*;
