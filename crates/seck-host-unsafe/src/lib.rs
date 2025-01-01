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

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod stub;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub use stub::*;
