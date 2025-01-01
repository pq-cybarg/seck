//! Non-Linux fallback. Real macOS implementation is in Plan 02 Task 3.

use std::os::fd::OwnedFd;
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

pub fn open_target(_path: &Path) -> Result<OwnedFd, ResolveError> {
    Err(ResolveError::Io(std::io::Error::other(
        "open_target not implemented on this platform; see Plan 02 for macOS",
    )))
}
