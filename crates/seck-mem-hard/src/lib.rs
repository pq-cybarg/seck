//! Memory-hardening helpers: mlock, madvise MADV_DONTDUMP, PR_SET_DUMPABLE.
//!
//! Unix-only. Best-effort: callers should treat failures as warnings
//! (e.g., mlock can fail on a process that has hit RLIMIT_MEMLOCK).

use zeroize::Zeroize;

#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error("mlock failed: {0}")]
    Mlock(std::io::Error),
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn lock_memory(ptr: *const u8, len: usize) -> Result<(), LockError> {
    if len == 0 {
        return Ok(());
    }
    // SAFETY: mlock takes a pointer + length to pages we already own.
    // Failure is returned via rc; we don't dereference or write.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::mlock(ptr as *const libc::c_void, len) };
    if rc != 0 {
        return Err(LockError::Mlock(std::io::Error::last_os_error()));
    }
    // Best-effort: madvise(MADV_DONTDUMP). Errors here are ignored.
    #[cfg(target_os = "linux")]
    {
        #[allow(unsafe_code)]
        let _ = unsafe { libc::madvise(ptr as *mut libc::c_void, len, libc::MADV_DONTDUMP) };
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn lock_memory(_ptr: *const u8, _len: usize) -> Result<(), LockError> {
    Ok(())
}

/// Apply process-level hardening: PR_SET_DUMPABLE=0 (no core dumps), and
/// suppress ptrace attach where possible.
pub fn harden_process() {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl with well-known op + valid args.
        #[allow(unsafe_code)]
        let _ = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    }
}

/// A locked, zeroize-on-drop byte buffer.
pub struct LockedBytes {
    bytes: Vec<u8>,
}

impl LockedBytes {
    pub fn new(bytes: Vec<u8>) -> Result<Self, LockError> {
        if !bytes.is_empty() {
            lock_memory(bytes.as_ptr(), bytes.len())?;
        }
        Ok(Self { bytes })
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for LockedBytes {
    fn drop(&mut self) {
        self.bytes.zeroize();
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if !self.bytes.is_empty() {
            // SAFETY: munlock on previously locked region.
            #[allow(unsafe_code)]
            let _ = unsafe {
                libc::munlock(
                    self.bytes.as_ptr() as *const libc::c_void,
                    self.bytes.capacity(),
                )
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_bytes_round_trip() {
        let lb = LockedBytes::new(b"secret".to_vec()).expect("lock");
        assert_eq!(lb.as_slice(), b"secret");
        drop(lb);
    }

    #[test]
    fn locked_empty_is_noop() {
        let _ = LockedBytes::new(Vec::new()).expect("empty");
    }
}
