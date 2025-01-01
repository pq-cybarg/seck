//! Property-based tests: adversarial filenames must never panic the
//! walker, and `WalkLimits` must be respected.

#![cfg(target_os = "linux")]

use proptest::prelude::*;
use seck_host::walker::{WalkLimits, walk};
use tempfile::TempDir;

proptest! {
    /// Adversarial single filenames (random printable ASCII without `/` or
    /// `\0`) never panic the walker. The walker either lists the file or
    /// drops it (e.g., due to weird chars); it must not abort.
    #[test]
    fn adversarial_filename_never_panics(
        name in "[\\x20-\\x7e]{1,128}"
    ) {
        // Strip any path-separators just in case the regex set produced one.
        let safe: String = name.chars().filter(|c| *c != '/' && *c != '\0').collect();
        if safe.is_empty() { return Ok(()); }
        let d = TempDir::new().unwrap();
        let f = d.path().join(format!("seck_{safe}"));
        if std::fs::write(&f, b"x").is_err() {
            // Some file systems reject characters we generated — fine.
            return Ok(());
        }
        let _ = walk(d.path(), WalkLimits::default());
    }

    /// Walk completes for arbitrary file counts up to a small bound and
    /// the result count matches what we wrote.
    #[test]
    fn small_directory_walk_matches_count(n in 0u32..32u32) {
        let d = TempDir::new().unwrap();
        for i in 0..n {
            std::fs::write(d.path().join(format!("f{i}")), b"x").unwrap();
        }
        let r = walk(d.path(), WalkLimits::default()).unwrap();
        prop_assert_eq!(r.len() as u32, n);
    }

    /// max_files limit triggers an error rather than silently truncating.
    #[test]
    fn max_files_is_enforced(extra in 0u32..8u32) {
        let limit: usize = 5;
        let d = TempDir::new().unwrap();
        for i in 0..(limit as u32 + extra + 1) {
            std::fs::write(d.path().join(format!("f{i}")), b"x").unwrap();
        }
        let r = walk(d.path(), WalkLimits {
            max_files: limit,
            max_bytes_per_file: 1 << 20,
            max_total_bytes: 1 << 20,
        });
        prop_assert!(r.is_err());
    }

    /// max_bytes_per_file triggers an error.
    #[test]
    fn max_bytes_per_file_is_enforced(extra in 1u32..64u32) {
        let d = TempDir::new().unwrap();
        let body: Vec<u8> = vec![b'x'; (16 + extra) as usize];
        std::fs::write(d.path().join("big"), &body).unwrap();
        let r = walk(d.path(), WalkLimits {
            max_files: 100,
            max_bytes_per_file: 16,
            max_total_bytes: 1 << 20,
        });
        prop_assert!(r.is_err());
    }
}
