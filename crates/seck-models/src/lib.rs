//! Local model manifest + verifier. The manifest (`models.manifest.toml`)
//! lists vetted open-weight models with pinned SHA3-256 hashes, source,
//! license, and recommended-RAM. `seck models pull` (Plan 09 net path,
//! in `seck-host-net`) downloads to the cache and verifies. This crate
//! is on the analysis path; `seck-host-net` is quarantined separately.

pub mod entry;
pub mod manifest;
pub mod recommend;
pub mod store;
pub mod verify;

pub use entry::Entry;
pub use manifest::{Manifest, parse};
