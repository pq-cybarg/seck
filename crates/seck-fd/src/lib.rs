//! Capability-typed file descriptors. Unix-only — `SandboxFd<Tag>` wraps
//! a raw FD from `std::os::fd`. On Windows the analogue is HANDLE-based
//! and lives in `seck-host::orchestrator_windows`; this crate compiles
//! to an empty lib there so `cargo check --workspace` succeeds.
//!
//! `SandboxFd<Tag>` proves a FD is owned by us and tagged with its role
//! (`Stdin`, `Report`, `Egress`). The only function that writes
//! `Tainted<Vec<u8>>` to anywhere is `write_to_sandbox_pipe`, which consumes
//! a `SandboxFd<Stdin>`. There is no other way to extract bytes from a
//! `Tainted`. This is the sole eliminator.
#![cfg(unix)]

use core::marker::PhantomData;
use nix::unistd::write;
use seck_taint::{FriendKey, SinkToken, Tainted};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

/// Marker: FD is the sandboxed child's stdin (FD 3 in the child).
pub struct Stdin;
/// Marker: FD is the sandboxed child's report-out pipe (FD 5 in the child).
pub struct Report;
/// Marker: FD is reserved for a future egress channel; not used in Plan 01.
pub struct Egress;

/// A FD we own that is destined for the sandboxed child.
pub struct SandboxFd<Tag> {
    fd: OwnedFd,
    _tag: PhantomData<Tag>,
}

impl<Tag> SandboxFd<Tag> {
    pub fn from_owned(fd: OwnedFd) -> Self {
        Self {
            fd,
            _tag: PhantomData,
        }
    }

    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    pub fn into_owned(self) -> OwnedFd {
        self.fd
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FdError {
    #[error("short write: wrote {wrote} of {expected} bytes")]
    ShortWrite { wrote: usize, expected: usize },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl From<nix::Error> for FdError {
    fn from(e: nix::Error) -> Self {
        FdError::Io(std::io::Error::from(e))
    }
}

/// The single sink for `Tainted<Vec<u8>>`. Consumes the tainted bytes; they
/// are dropped (zeroized) after the write completes.
pub fn write_to_sandbox_pipe(
    bytes: Tainted<Vec<u8>>,
    fd: &SandboxFd<Stdin>,
) -> Result<(), FdError> {
    let token = SinkToken::__new_friend(FriendKey::FOR_SECK_FD);
    let inner = bytes.__into_inner_for_sink(token);
    let expected = inner.len();
    let mut written = 0usize;
    while written < expected {
        let n = write(fd.as_fd(), &inner[written..])?;
        if n == 0 {
            return Err(FdError::ShortWrite {
                wrote: written,
                expected,
            });
        }
        written += n;
    }
    Ok(())
}

/// Host-side pipe FD, used to read from the sandbox's pipes (e.g., reading
/// the report JSON the sandbox emits on FD 5).
pub struct HostPipeFd<Tag> {
    fd: OwnedFd,
    _tag: PhantomData<Tag>,
}

impl<Tag> HostPipeFd<Tag> {
    pub fn from_owned(fd: OwnedFd) -> Self {
        Self {
            fd,
            _tag: PhantomData,
        }
    }

    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    pub fn into_owned(self) -> OwnedFd {
        self.fd
    }
}
