//! macOS Seatbelt sandbox via `sandbox_init_with_parameters`.
//!
//! The C API is in libSystem (declared in <sandbox.h>, technically
//! deprecated but functional through macOS 26). We pass the bundled SBPL
//! profile (platform/macos/seatbelt.sb) and two parameters: MODEL_DIR
//! (read-only access) and INFER_BIN (the one binary we may exec).

use seck_plugin::SandboxBackend;

pub struct MacosSandbox {
    profile_hash: [u8; 32],
}

impl MacosSandbox {
    pub fn new() -> Self {
        Self {
            profile_hash: crate::bundled_profile_hash(),
        }
    }

    /// Apply Seatbelt to the current process.
    pub fn apply_self_lockdown(
        model_dir: &std::path::Path,
        infer_bin: &std::path::Path,
    ) -> Result<(), anyhow::Error> {
        let profile = include_str!("../../../platform/macos/seatbelt.sb");
        let cprofile = std::ffi::CString::new(profile)?;
        let cmodel = std::ffi::CString::new(model_dir.as_os_str().as_encoded_bytes())?;
        let cinfer = std::ffi::CString::new(infer_bin.as_os_str().as_encoded_bytes())?;

        // sandbox_init_with_parameters takes a NULL-terminated array of
        // ("KEY", "VALUE", "KEY2", "VALUE2", ..., NULL).
        let model_key = std::ffi::CString::new("MODEL_DIR")?;
        let infer_key = std::ffi::CString::new("INFER_BIN")?;
        let params: [*const libc::c_char; 5] = [
            model_key.as_ptr(),
            cmodel.as_ptr(),
            infer_key.as_ptr(),
            cinfer.as_ptr(),
            std::ptr::null(),
        ];

        let mut errbuf: *mut libc::c_char = std::ptr::null_mut();
        // SAFETY: extern from libsystem_sandbox. We pass a valid NUL-terminated
        // profile string, a NULL-terminated parameter array, and a pointer to
        // a pointer for the error message. We check the return value.
        #[allow(unsafe_code)]
        let rc = unsafe {
            sandbox_init_with_parameters(cprofile.as_ptr(), 0, params.as_ptr(), &mut errbuf)
        };
        if rc != 0 {
            let err = if errbuf.is_null() {
                "unknown sandbox error (errbuf was NULL)".to_string()
            } else {
                // SAFETY: errbuf is a NUL-terminated C string allocated by
                // the sandbox library; we copy it into a Rust String and free
                // it via sandbox_free_error.
                #[allow(unsafe_code)]
                let s = unsafe {
                    std::ffi::CStr::from_ptr(errbuf)
                        .to_string_lossy()
                        .into_owned()
                };
                #[allow(unsafe_code)]
                unsafe {
                    sandbox_free_error(errbuf)
                };
                s
            };
            return Err(anyhow::anyhow!(
                "sandbox_init_with_parameters: {err}"
            ));
        }
        Ok(())
    }
}

impl SandboxBackend for MacosSandbox {
    fn name(&self) -> &'static str {
        "macos-seatbelt"
    }

    fn profile_sha3_256(&self) -> [u8; 32] {
        self.profile_hash
    }
}

// libSystem (already linked by the Rust runtime on macOS). The
// `sandbox_init_with_parameters` and `sandbox_free_error` symbols are
// in /usr/lib/system/libsystem_sandbox.dylib.
#[allow(unsafe_code)]
#[link(name = "System", kind = "dylib")]
unsafe extern "C" {
    fn sandbox_init_with_parameters(
        profile: *const libc::c_char,
        flags: u64,
        parameters: *const *const libc::c_char,
        errorbuf: *mut *mut libc::c_char,
    ) -> i32;
    fn sandbox_free_error(errbuf: *mut libc::c_char);
}
