//! Safe path resolution. The single crate that holds `unsafe` code in
//! Plan 01. Linux uses `openat2(RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS |
//! RESOLVE_BENEATH | RESOLVE_NO_XDEV)`; macOS and others get a `cfg`-gated
//! fallback that's implemented in Plan 02.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(not(target_os = "linux"))]
mod stub;
#[cfg(not(target_os = "linux"))]
pub use stub::*;
