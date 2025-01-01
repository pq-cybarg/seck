//! Host-side orchestration. Opens files safely, builds Tainted FileSets,
//! spawns the sandboxed reader, pipes bytes in, reads the report out.
//!
//! The host crate is `#![forbid(unsafe_code)]`-equivalent (via workspace
//! lint `unsafe_code = "deny"`); all unsafe is quarantined in
//! `seck-host-unsafe`.

pub mod fileset;
pub mod walker;
