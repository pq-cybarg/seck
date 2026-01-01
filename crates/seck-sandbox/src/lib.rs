//! Sandbox backends. Plan 01: Linux Landlock + PR_SET_NO_NEW_PRIVS + (x86) PR_SET_TSC.
//! Plan 02: macOS Seatbelt (sandbox_init_with_parameters + system.sb base).
//! Approach B (capability split) and Approach C (container) arrive in later plans.

use seck_plugin::SandboxBackend;
use sha3::{Digest, Sha3_256};

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux::LinuxSandbox;

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use macos::MacosSandbox;

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use windows::WindowsSandbox;

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub mod stub;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub use stub::LinuxSandbox;

pub mod container;
pub use container::ContainerSandbox;

/// SHA3-256 hash of the profile files bundled into the binary for the
/// current platform. Reported in `sandbox_attestation` so a third party
/// can verify which profile version was active.
pub fn bundled_profile_hash() -> [u8; 32] {
    let mut h = Sha3_256::new();
    #[cfg(target_os = "linux")]
    {
        h.update(include_bytes!("../../../platform/linux/seccomp.bpf.toml"));
        h.update(include_bytes!("../../../platform/linux/landlock.toml"));
    }
    #[cfg(target_os = "macos")]
    {
        h.update(include_bytes!("../../../platform/macos/seatbelt.sb"));
    }
    #[cfg(target_os = "windows")]
    {
        h.update(b"windows-appcontainer-v1");
    }
    h.finalize().into()
}

/// Apply the platform's primary sandbox to the current process. Called
/// from `seck-reader`'s main() right after FD inheritance.
#[cfg(target_os = "linux")]
pub fn apply_self_lockdown() -> Result<(), anyhow::Error> {
    LinuxSandbox::apply_self_lockdown()
}

#[cfg(target_os = "macos")]
pub fn apply_self_lockdown() -> Result<(), anyhow::Error> {
    let model_dir = std::env::var("SECK_MODEL_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/tmp"));
    let infer_bin = std::env::var("SECK_INFER_BIN")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/usr/bin/true"));
    MacosSandbox::apply_self_lockdown(&model_dir, &infer_bin)
}

#[cfg(target_os = "windows")]
pub fn apply_self_lockdown() -> Result<(), anyhow::Error> {
    WindowsSandbox::apply_self_lockdown()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn apply_self_lockdown() -> Result<(), anyhow::Error> {
    Err(anyhow::anyhow!("no sandbox backend for this platform"))
}

/// Helper: build a sandbox backend for the current platform.
pub fn default_backend() -> Box<dyn SandboxBackend> {
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxSandbox::new())
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(MacosSandbox::new())
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(WindowsSandbox::new())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Box::new(stub::LinuxSandbox::new())
    }
}
