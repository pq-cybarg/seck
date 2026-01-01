//! `FileSet` — a typed bag of `Tainted<Vec<u8>>` byte payloads paired with
//! validated relative paths. Built from a `walker::Entry` stream.

use crate::walker::Entry;
use seck_taint::{Tainted, Untainted};
use std::path::PathBuf;

pub struct FileEntry {
    pub relative: Untainted<PathBuf>,
    pub bytes: Tainted<Vec<u8>>,
    pub size: u64,
}

pub struct FileSet {
    entries: Vec<FileEntry>,
}

impl FileSet {
    pub fn entries(&self) -> &[FileEntry] {
        &self.entries
    }

    pub fn into_entries(self) -> Vec<FileEntry> {
        self.entries
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FileSetError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("nix: {0}")]
    Nix(#[from] nix::Error),
}

pub fn build_fileset(walked: Vec<Entry>) -> Result<FileSet, FileSetError> {
    let mut out = Vec::with_capacity(walked.len());
    for e in walked {
        let mut buf = Vec::with_capacity(e.size as usize);
        let mut tmp = [0u8; 8192];
        loop {
            let n = nix::unistd::read(&e.fd, &mut tmp)?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() >= e.size as usize {
                buf.truncate(e.size as usize);
                break;
            }
        }
        out.push(FileEntry {
            relative: Untainted::new(e.relative),
            bytes: Tainted::__new_internal(buf),
            size: e.size,
        });
    }
    Ok(FileSet { entries: out })
}
