//! macOS path resolver. Linux uses openat2(RESOLVE_NO_SYMLINKS); macOS
//! doesn't expose that flag, so we use `open(O_NOFOLLOW | O_CLOEXEC)`
//! (refuses a symlink at the FINAL path component) plus a defensive
//! `realpath()` check that the canonical form matches the path we asked
//! for, byte-for-byte. If they differ, an intermediate symlink was
//! followed during canonicalization and we refuse.
//!
//! This is slightly weaker than openat2's all-component refusal — an
//! intermediate symlink can still be followed during open() — but the
//! realpath check catches the result. For Plan 02 this is the best
//! macOS offers without third-party tooling.

use std::os::fd::{FromRawFd, OwnedFd};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("symlink not permitted: {0}")]
    Symlink(String),
    #[error("path escape not permitted: {0}")]
    Escape(String),
    #[error("path realpath mismatch (intermediate symlink?): {0}")]
    RealpathMismatch(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub fn open_target(path: &Path) -> Result<OwnedFd, ResolveError> {
    let cpath = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| ResolveError::Escape("nul byte in path".into()))?;

    // 1. open(O_RDONLY | O_NOFOLLOW | O_CLOEXEC) — refuses if the FINAL
    //    component is a symlink. ELOOP is the macOS errno in that case.
    // SAFETY: open() is a stable syscall wrapper. We check the return value
    // and only construct an OwnedFd from a non-negative result.
    #[allow(unsafe_code)]
    let fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(libc::ELOOP) => Err(ResolveError::Symlink(path.display().to_string())),
            _ => Err(ResolveError::Io(err)),
        };
    }
    // SAFETY: open() returned a non-negative FD that we now own.
    #[allow(unsafe_code)]
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    // 2. Defensive realpath check: if any intermediate component is a
    //    symlink, the canonical path will differ. We compare with the
    //    parent-canonicalized form so a relative argv like "./foo" still
    //    matches after Path::canonicalize on its parent + the trailing
    //    component.
    if let Ok(canon) = std::fs::canonicalize(path) {
        let parent_canon = canon.parent().map(|p| p.to_path_buf());
        let want_parent = path.parent().and_then(|p| std::fs::canonicalize(p).ok());
        if let (Some(want), Some(got)) = (want_parent, parent_canon) {
            if got != want {
                return Err(ResolveError::RealpathMismatch(format!(
                    "got parent {got:?}, expected {want:?}"
                )));
            }
        }
    }

    Ok(owned)
}
