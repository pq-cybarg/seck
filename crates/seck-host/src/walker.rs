//! Directory walking with size/count limits and symlink refusal.

use seck_host_unsafe::open_target;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy)]
pub struct WalkLimits {
    pub max_files: usize,
    pub max_bytes_per_file: usize,
    pub max_total_bytes: usize,
}

impl Default for WalkLimits {
    fn default() -> Self {
        Self {
            max_files: 10_000,
            max_bytes_per_file: 16 * 1024 * 1024,
            max_total_bytes: 256 * 1024 * 1024,
        }
    }
}

pub struct Entry {
    pub relative: PathBuf,
    pub fd: OwnedFd,
    pub size: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum WalkError {
    #[error("limit exceeded: {0}")]
    Limit(String),
    #[error("path resolver: {0}")]
    Resolve(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub fn walk(root: &Path, limits: WalkLimits) -> Result<Vec<Entry>, WalkError> {
    let mut out = Vec::new();
    let mut total = 0u64;
    walk_inner(root, root, &mut out, &mut total, limits)?;
    Ok(out)
}

fn walk_inner(
    root: &Path,
    current: &Path,
    out: &mut Vec<Entry>,
    total: &mut u64,
    limits: WalkLimits,
) -> Result<(), WalkError> {
    let md = std::fs::symlink_metadata(current)?;
    if md.is_symlink() {
        // Refuse silently: caller asked us not to follow.
        return Ok(());
    }
    if md.is_dir() {
        for entry in std::fs::read_dir(current)? {
            let entry = entry?;
            if out.len() >= limits.max_files {
                return Err(WalkError::Limit("max_files".into()));
            }
            walk_inner(root, &entry.path(), out, total, limits)?;
        }
    } else if md.is_file() {
        if md.len() as usize > limits.max_bytes_per_file {
            return Err(WalkError::Limit(format!(
                "file size {} > {}",
                md.len(),
                limits.max_bytes_per_file
            )));
        }
        *total += md.len();
        if *total as usize > limits.max_total_bytes {
            return Err(WalkError::Limit("max_total_bytes".into()));
        }
        let fd = open_target(current).map_err(|e| WalkError::Resolve(format!("{e}")))?;
        let mut relative = current.strip_prefix(root).unwrap_or(current).to_path_buf();
        // If the caller passed a single file (root == current), the strip_prefix
        // result is an empty path. Use the file name in that case so the report
        // and prompt have a sensible "path" field.
        if relative.as_os_str().is_empty() {
            if let Some(name) = current.file_name() {
                relative = name.into();
            }
        }
        out.push(Entry {
            relative,
            fd,
            size: md.len(),
        });
    }
    Ok(())
}
