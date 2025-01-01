//! Host-side orchestration. Opens files safely, builds Tainted FileSets,
//! spawns the sandboxed reader, pipes bytes in, reads the report out.
//!
//! Workspace lint `unsafe_code = "deny"` keeps this crate clean; all
//! unsafe is quarantined in `seck-host-unsafe`.

#[cfg(unix)]
pub mod fileset;
#[cfg(unix)]
pub mod walker;
#[cfg(unix)]
pub mod orchestrator;

#[cfg(target_os = "windows")]
pub mod orchestrator_windows;
