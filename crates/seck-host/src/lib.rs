//! Host-side orchestration. Opens files safely, builds Tainted FileSets,
//! spawns the sandboxed reader, pipes bytes in, reads the report out.
//!
//! Workspace lint `unsafe_code = "deny"` keeps this crate clean; all
//! unsafe is quarantined in `seck-host-unsafe`.

pub mod fileset;
pub mod orchestrator;
pub mod walker;
