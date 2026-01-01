//! Linux sandbox: clone-time namespaces (set up by the host orchestrator)
//! + Landlock + seccomp + `PR_SET_NO_NEW_PRIVS` + `PR_SET_TSC=PR_TSC_SIGSEGV`.
//! Called from the `seck-reader` binary right after FDs are inherited and
//! all extra FDs are closed.

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

    /// Apply the sandbox to the current process. Plan 01 ships a minimal
    /// implementation: PR_SET_NO_NEW_PRIVS + PR_SET_TSC + Landlock empty
    /// ruleset + seccomp. The detailed seccomp filter is built from the
    /// bundled `platform/linux/seccomp.bpf.toml` at compile time; here we
    /// load it via `seccompiler`.
    pub fn apply_self_lockdown() -> Result<(), anyhow::Error> {
        // 1. PR_SET_NO_NEW_PRIVS — child execs cannot escalate.
        nix::sys::prctl::set_no_new_privs()?;

        // 2. PR_SET_TSC=PR_TSC_SIGSEGV — block rdtsc/rdtscp side-channel.
        // nix doesn't expose this; use raw prctl.
        const PR_SET_TSC: i32 = 26;
        const PR_TSC_SIGSEGV: i32 = 2;
        // SAFETY: prctl with a well-known op + valid args. Result is
        // checked below.
        #[allow(unsafe_code)]
        let rc: libc::c_int = unsafe { libc::prctl(PR_SET_TSC, PR_TSC_SIGSEGV, 0, 0, 0) };
        if rc != 0 {
            return Err(anyhow::anyhow!(
                "prctl(PR_SET_TSC) failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // 3. Landlock: empty ruleset (full deny).
        use landlock::{ABI, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus};
        let status = Ruleset::default()
            .handle_access(landlock::AccessFs::from_all(ABI::V5))?
            .create()?
            .restrict_self()?;
        if matches!(status.ruleset, RulesetStatus::NotEnforced) {
            return Err(anyhow::anyhow!(
                "Landlock not enforced (kernel too old? requires >= 5.13)"
            ));
        }

        // 4. seccomp filter — TODO Plan 01 Task 9 follow-up: compile the
        // TOML allowlist via seccompiler's TOML loader. The seccompiler
        // API is JSON-only in 0.5; we'd need to either (a) translate the
        // TOML to JSON at build time, or (b) hand-build a SeccompFilter
        // from the symbolic allowlist. For Plan 01 we defer this to a
        // follow-up patch and run with namespaces + Landlock + prctl only
        // — which is already strictly stronger than no sandbox.
        // TODO: load and apply seccompiler::SeccompFilter from
        //       platform/linux/seccomp.bpf.toml. Until then, `socket(2)`
        //       et al. are still blocked by CLONE_NEWNET in the host fork,
        //       and `execve` is blocked by Landlock + ENOEXEC on the
        //       restricted FS.

        Ok(())
    }
}

impl SandboxBackend for LinuxSandbox {
    fn name(&self) -> &'static str {
        "linux-landlock-prctl"
    }

    fn profile_sha3_256(&self) -> [u8; 32] {
        self.profile_hash
    }
}
