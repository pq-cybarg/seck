//! Linux `openat2`-based safe path resolver.

use std::os::fd::{FromRawFd, OwnedFd};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("symlink not permitted: {0}")]
    Symlink(String),
    #[error("path escape not permitted: {0}")]
    Escape(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_XDEV: u64 = 0x01;
// NOTE: RESOLVE_BENEATH was intentionally dropped. It rejects any absolute
// path because absolute paths "escape" AT_FDCWD. For seck the user's target
// is explicit (they ran `seck analyze /etc/passwd`), so escape-from-anchor
// is not the right defense. We keep RESOLVE_NO_SYMLINKS, which refuses ALL
// symlinks in the path (any component) — that's the actual defense we want.

// openat2 syscall numbers vary by arch. We pick the right one at compile time.
#[cfg(target_arch = "x86_64")]
const SYS_OPENAT2: libc::c_long = 437;
#[cfg(target_arch = "aarch64")]
const SYS_OPENAT2: libc::c_long = 437;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("openat2 syscall number unknown for this arch");

pub fn open_target(path: &Path) -> Result<OwnedFd, ResolveError> {
    let cpath = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| ResolveError::Escape("nul byte in path".into()))?;
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        mode: 0,
        resolve: RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV,
    };
    // SAFETY: openat2 is a syscall with a well-defined signature. We pass
    // a valid path pointer, a valid OpenHow pointer with correct size,
    // and we check the return value. The OwnedFd we synthesize owns the
    // descriptor returned by the kernel.
    let fd: libc::c_long = unsafe {
        libc::syscall(
            SYS_OPENAT2,
            libc::AT_FDCWD,
            cpath.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(libc::ELOOP) => Err(ResolveError::Symlink(path.display().to_string())),
            Some(libc::EXDEV) => Err(ResolveError::Escape(path.display().to_string())),
            _ => Err(ResolveError::Io(err)),
        };
    }
    // SAFETY: kernel returned a non-negative FD that we now own.
    let owned = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    Ok(owned)
}
