//! Sandbox backends. Plan 01 ships the Linux backend (Landlock + seccomp +
//! `PR_SET_TSC=PR_TSC_SIGSEGV` + `PR_SET_NO_NEW_PRIVS`). macOS / container
//! / Approach B are added in later plans.

use seck_plugin::SandboxBackend;
use sha3::{Digest, Sha3_256};

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "linux")]
pub use linux::LinuxSandbox;

#[cfg(not(target_os = "linux"))]
pub mod stub;
#[cfg(not(target_os = "linux"))]
pub use stub::LinuxSandbox;

/// SHA3-256 hash of the two profile files bundled into the binary.
pub fn bundled_profile_hash() -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(include_bytes!("../../../platform/linux/seccomp.bpf.toml"));
    h.update(include_bytes!("../../../platform/linux/landlock.toml"));
    h.finalize().into()
}

/// Helper: build a sandbox backend for Plan 01 (Linux only at runtime).
pub fn default_backend() -> Box<dyn SandboxBackend> {
    Box::new(LinuxSandbox::new())
}
