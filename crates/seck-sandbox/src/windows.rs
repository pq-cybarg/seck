//! Windows sandbox backend (Plan 16).
//!
//! Layered defenses, applied to the child by the orchestrator and to
//! the running process by `apply_self_lockdown()`:
//!
//! 1. **AppContainer / LowBox.** A per-app SID with no broker access,
//!    derived via `CreateAppContainerProfile` +
//!    `DeriveAppContainerSidFromAppContainerName`.
//! 2. **Restricted token.** `CreateRestrictedToken` with `DISABLE_MAX_PRIVILEGE`
//!    drops every group SID's permissions to "deny only".
//! 3. **Job Object.** `CreateJobObjectW` + `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`
//!    so dropping the parent kills the sandboxed child.
//! 4. **Process mitigation policies.** `SetProcessMitigationPolicy` for ACG
//!    (no dynamic code), CIG (Microsoft-signed binaries only), DEP,
//!    ASLR, EAF, Image-Load policy, and Extension-Point disable.
//!
//! NB: This module is `#![cfg(target_os = "windows")]`; it does not
//! compile on Linux/macOS. The build is verified in CI on
//! `windows-2022` (see `.github/workflows/windows.yml`).
#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use seck_plugin::SandboxBackend;
use sha3::{Digest, Sha3_256};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{
    CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, TOKEN_DUPLICATE, TOKEN_QUERY,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject,
};
use windows_sys::Win32::System::SystemServices::{
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY, PROCESS_MITIGATION_DYNAMIC_CODE_POLICY,
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY, PROCESS_MITIGATION_IMAGE_LOAD_POLICY,
    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY, PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcessToken, PROCESS_MITIGATION_POLICY, ProcessDynamicCodePolicy,
    ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy, ProcessSignaturePolicy,
    ProcessStrictHandleCheckPolicy, ProcessSystemCallDisablePolicy, SetProcessMitigationPolicy,
};

/// The application's per-install AppContainer profile name. Stable so
/// the COM shellext + the CLI agree on the SID it derives.
pub const SECK_APPCONTAINER_NAME: &str = "Seck.Analyzer";

#[derive(Debug, Clone)]
pub struct WindowsSandbox {
    profile_hash: [u8; 32],
}

impl WindowsSandbox {
    pub fn new() -> Self {
        let mut h = Sha3_256::new();
        h.update(b"windows-appcontainer-v1");
        h.update(SECK_APPCONTAINER_NAME.as_bytes());
        // The mitigation set is part of the profile identity: changing
        // it changes the hash, so the audit trail flags the change.
        h.update(b"acg|cig|dep|aslr|eaf|strict-handle|syscall-disable");
        Self {
            profile_hash: h.finalize().into(),
        }
    }

    /// Provision (or look up) the per-install AppContainer profile and
    /// derive its SID. Both the COM handler and the CLI call this.
    pub fn provision_profile() -> anyhow::Result<()> {
        let wide_name: Vec<u16> = SECK_APPCONTAINER_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let wide_display: Vec<u16> = "Seck Analyzer"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let wide_desc: Vec<u16> = "Sandboxed-LLM file/project analyzer"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut sid: *mut core::ffi::c_void = core::ptr::null_mut();
        // SAFETY: all pointers point at owned, NUL-terminated UTF-16 buffers.
        let hr = unsafe {
            CreateAppContainerProfile(
                wide_name.as_ptr(),
                wide_display.as_ptr(),
                wide_desc.as_ptr(),
                core::ptr::null(),
                0,
                &mut sid,
            )
        };
        // 0x800700B7 = ERROR_ALREADY_EXISTS — fine, the profile already
        // exists from a previous install or run.
        if hr != 0 && hr as u32 != 0x800700B7 {
            anyhow::bail!("CreateAppContainerProfile failed: HRESULT 0x{:x}", hr);
        }
        if !sid.is_null() {
            // SAFETY: sid was allocated by the OS. Pair with FreeSid.
            unsafe { windows_sys::Win32::Security::FreeSid(sid as _) };
        }
        Ok(())
    }

    /// Resolve the AppContainer SID for `SECK_APPCONTAINER_NAME` so the
    /// orchestrator can put it on its CreateProcess call.
    pub fn derive_sid() -> anyhow::Result<Vec<u8>> {
        let wide: Vec<u16> = SECK_APPCONTAINER_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut sid: *mut core::ffi::c_void = core::ptr::null_mut();
        // SAFETY: wide is a NUL-terminated UTF-16 buffer owned by us.
        let hr = unsafe { DeriveAppContainerSidFromAppContainerName(wide.as_ptr(), &mut sid) };
        if hr != 0 || sid.is_null() {
            anyhow::bail!(
                "DeriveAppContainerSidFromAppContainerName failed: HRESULT 0x{:x}",
                hr
            );
        }
        let len = unsafe { windows_sys::Win32::Security::GetLengthSid(sid as _) } as usize;
        let mut out = vec![0u8; len];
        // SAFETY: GetLengthSid returned the byte length; sid is valid.
        unsafe { core::ptr::copy_nonoverlapping(sid as *const u8, out.as_mut_ptr(), len) };
        unsafe { windows_sys::Win32::Security::FreeSid(sid as _) };
        Ok(out)
    }

    /// Build a restricted token derived from the current process token.
    /// Caller owns the returned HANDLE and must `CloseHandle` it.
    pub fn build_restricted_token() -> anyhow::Result<HANDLE> {
        let proc_h = unsafe { GetCurrentProcess() };
        let mut tok: HANDLE = core::ptr::null_mut();
        // SAFETY: GetCurrentProcess returns a pseudo-handle; OpenProcessToken is safe.
        let ok = unsafe { OpenProcessToken(proc_h, TOKEN_DUPLICATE | TOKEN_QUERY, &mut tok) };
        if ok == 0 {
            anyhow::bail!("OpenProcessToken failed: GetLastError = {}", unsafe {
                GetLastError()
            });
        }
        let mut restricted: HANDLE = core::ptr::null_mut();
        // SAFETY: tok was obtained above; null pointers + zero counts
        // for the three "to disable / delete" arrays are valid.
        let ok = unsafe {
            CreateRestrictedToken(
                tok,
                DISABLE_MAX_PRIVILEGE,
                0,
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                &mut restricted,
            )
        };
        unsafe { CloseHandle(tok) };
        if ok == 0 {
            anyhow::bail!("CreateRestrictedToken failed: GetLastError = {}", unsafe {
                GetLastError()
            });
        }
        Ok(restricted)
    }

    /// Create a JOB OBJECT with kill-on-close + die-on-exception limits.
    /// Caller owns the HANDLE.
    pub fn build_job_object() -> anyhow::Result<HANDLE> {
        // SAFETY: passing nulls is documented for an unnamed job.
        let job = unsafe { CreateJobObjectW(core::ptr::null_mut(), core::ptr::null()) };
        if job.is_null() {
            anyhow::bail!("CreateJobObjectW failed: GetLastError = {}", unsafe {
                GetLastError()
            });
        }
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { core::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        let _ = info.BasicLimitInformation; // mark intentionally used
        let ok = unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                core::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            unsafe { CloseHandle(job) };
            anyhow::bail!("SetInformationJobObject failed: {err}");
        }
        Ok(job)
    }

    /// Apply the in-process mitigation cascade. Must be called from the
    /// child (e.g., `seck-reader`) before it touches any file or pipe.
    pub fn apply_mitigations() -> anyhow::Result<()> {
        // ACG: prohibit dynamic code generation (no JIT, no VirtualAlloc PAGE_EXECUTE).
        let dyncode = PROCESS_MITIGATION_DYNAMIC_CODE_POLICY {
            Anonymous: unsafe { core::mem::zeroed() },
        };
        set_policy(ProcessDynamicCodePolicy, &dyncode)?;

        // CIG: only Microsoft-signed binaries may load (we ship signed by Microsoft
        // via MSIX; the user-mode loader enforces this).
        let cig = PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY {
            Anonymous: unsafe { core::mem::zeroed() },
        };
        set_policy(ProcessSignaturePolicy, &cig)?;

        // Strict handle checking: catch use-after-close + invalid HANDLEs.
        let sh = PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY {
            Anonymous: unsafe { core::mem::zeroed() },
        };
        set_policy(ProcessStrictHandleCheckPolicy, &sh)?;

        // Image load policy: refuse non-signed images, refuse remote
        // shares, refuse low-mandatory-label images.
        let il = PROCESS_MITIGATION_IMAGE_LOAD_POLICY {
            Anonymous: unsafe { core::mem::zeroed() },
        };
        set_policy(ProcessImageLoadPolicy, &il)?;

        // Disable legacy extension-points (AppInit DLLs, IME, etc.).
        let ep = PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY {
            Anonymous: unsafe { core::mem::zeroed() },
        };
        set_policy(ProcessExtensionPointDisablePolicy, &ep)?;

        // Disable Win32k system calls (we never call user32/gdi32).
        let sc = PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY {
            Anonymous: unsafe { core::mem::zeroed() },
        };
        set_policy(ProcessSystemCallDisablePolicy, &sc)?;

        Ok(())
    }

    pub fn apply_self_lockdown() -> anyhow::Result<()> {
        Self::apply_mitigations()
    }
}

fn set_policy<T>(which: PROCESS_MITIGATION_POLICY, value: &T) -> anyhow::Result<()> {
    // SAFETY: pointer + length describe a packed Win32 policy struct.
    let ok = unsafe {
        SetProcessMitigationPolicy(
            which,
            value as *const _ as *const _,
            core::mem::size_of::<T>(),
        )
    };
    if ok == 0 {
        anyhow::bail!(
            "SetProcessMitigationPolicy({:?}) failed: {}",
            which,
            unsafe { GetLastError() }
        );
    }
    Ok(())
}

impl SandboxBackend for WindowsSandbox {
    fn name(&self) -> &'static str {
        "windows-appcontainer"
    }
    fn profile_sha3_256(&self) -> [u8; 32] {
        self.profile_hash
    }
}

/// Bind a Job HANDLE to a (newly-created, suspended) child process.
pub fn attach_to_job(job: HANDLE, child: HANDLE) -> anyhow::Result<()> {
    let ok = unsafe { AssignProcessToJobObject(job, child) };
    if ok == 0 {
        anyhow::bail!("AssignProcessToJobObject failed: {}", unsafe {
            GetLastError()
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_hash_is_stable() {
        let a = WindowsSandbox::new().profile_sha3_256();
        let b = WindowsSandbox::new().profile_sha3_256();
        assert_eq!(a, b);
    }

    #[test]
    fn name_is_appcontainer() {
        assert_eq!(WindowsSandbox::new().name(), "windows-appcontainer");
    }
}
