//! Host→reader FD-3 wire format.
//!
//! Frame layout (little-endian):
//! ```text
//! header   := magic[4]="SECK" | version[2]=1 | rsv[2]=0 | n_entries[4]
//! entry    := pathlen[4] | path[pathlen utf8] | bytelen[8] | bytes[bytelen]
//! trailer  := magic[4]="DONE"
//! ```
//!
//! Tainted file bytes appear only in the `bytes[bytelen]` field.
//! Paths are host-validated Untainted before serialization.

pub const MAGIC_HEADER: &[u8; 4] = b"SECK";
pub const MAGIC_TRAILER: &[u8; 4] = b"DONE";
pub const VERSION: u16 = 1;

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("bad magic")]
    BadMagic,
    #[error("unsupported version: {0}")]
    BadVersion(u16),
    #[error("short read")]
    ShortRead,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid utf8 in path")]
    BadPath,
    #[error("frame too large: {0}")]
    TooLarge(u64),
}

/// Maximum bytes in a single entry, as a defense-in-depth limit beyond the
/// host's WalkLimits. Lined up with the spec's per-file max.
pub const MAX_ENTRY_BYTES: u64 = 16 * 1024 * 1024;

/// Maximum entries in one frame stream.
pub const MAX_ENTRIES: u32 = 10_000;

/// Maximum path length in bytes.
pub const MAX_PATH_LEN: u32 = 4096;
