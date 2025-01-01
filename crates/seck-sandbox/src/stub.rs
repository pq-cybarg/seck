//! Non-Linux fallback. macOS Seatbelt arrives in Plan 02; the container
//! backend arrives in Plan 03. On this build the "sandbox" is a no-op
//! that returns an error if you try to apply it — so the host orchestrator
//! refuses to spawn the reader on non-Linux until Plan 02 lands.

use seck_plugin::SandboxBackend;

pub struct LinuxSandbox {
    profile_hash: [u8; 32],
}

impl LinuxSandbox {
    pub fn new() -> Self {
        Self {
            profile_hash: crate::bundled_profile_hash(),
        }
    }

    pub fn apply_self_lockdown() -> Result<(), anyhow::Error> {
        Err(anyhow::anyhow!(
            "Linux sandbox not available on this platform; see Plan 02 for macOS Seatbelt"
        ))
    }
}

impl SandboxBackend for LinuxSandbox {
    fn name(&self) -> &'static str {
        "stub-non-linux"
    }

    fn profile_sha3_256(&self) -> [u8; 32] {
        self.profile_hash
    }
}
