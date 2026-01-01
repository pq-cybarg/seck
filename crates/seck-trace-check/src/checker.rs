//! `check_trace` — the Rust analog of `Trace.checkIOBoundary`.
//!
//! Given a parsed `Effect` stream and a `canary` byte sequence known to
//! originate from a user-supplied file, assert that the canary never
//! appears in (a) any `OpenP` path, (b) any `ExecP` path/argv/env, or
//! (c) any `NetConn` host. Also assert that there are no `NetConn`
//! steps at all. Tainted writes are permitted only on FD 3 or FD 5.

use crate::strace_parse::Effect;

/// FDs to which a tainted byte may legally flow.
pub const ALLOWED_TAINTED_WRITE_FDS: &[i32] = &[3, 5];

#[derive(Debug, thiserror::Error)]
pub enum InvariantError {
    #[error("tainted byte found in open path: {}", String::from_utf8_lossy(.0))]
    TaintedOpen(Vec<u8>),
    #[error(
        "tainted byte found in execve path/argv/env: {}",
        String::from_utf8_lossy(.0)
    )]
    TaintedExec(Vec<u8>),
    #[error("network connection observed (forbidden): {host}:{port}")]
    Net { host: String, port: u16 },
    #[error("tainted byte written to unauthorized fd {0}")]
    UnauthorizedWrite(i32),
}

pub fn check_trace(effects: &[Effect], canary: &[u8]) -> Result<(), InvariantError> {
    for e in effects {
        match e {
            Effect::OpenP { path } if contains_subsequence(path, canary) => {
                return Err(InvariantError::TaintedOpen(path.clone()));
            }
            Effect::ExecP { path, args, env } => {
                if contains_subsequence(path, canary) {
                    return Err(InvariantError::TaintedExec(path.clone()));
                }
                for a in args {
                    if contains_subsequence(a, canary) {
                        return Err(InvariantError::TaintedExec(a.clone()));
                    }
                }
                for (k, v) in env {
                    if contains_subsequence(k, canary) {
                        return Err(InvariantError::TaintedExec(k.clone()));
                    }
                    if contains_subsequence(v, canary) {
                        return Err(InvariantError::TaintedExec(v.clone()));
                    }
                }
            }
            Effect::NetConn { host, port } => {
                return Err(InvariantError::Net {
                    host: host.clone(),
                    port: *port,
                });
            }
            Effect::WriteF { fd, bytes }
                if contains_subsequence(bytes, canary)
                    && !ALLOWED_TAINTED_WRITE_FDS.contains(fd) =>
            {
                return Err(InvariantError::UnauthorizedWrite(*fd));
            }
            _ => {}
        }
    }
    Ok(())
}

fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_needle_no_match() {
        assert!(!contains_subsequence(b"abc", b""));
    }

    #[test]
    fn finds_subseq() {
        assert!(contains_subsequence(b"hello world", b"o w"));
    }

    #[test]
    fn writes_to_fd3_ok() {
        let effs = vec![Effect::WriteF { fd: 3, bytes: b"CANARY".to_vec() }];
        assert!(check_trace(&effs, b"CANARY").is_ok());
    }

    #[test]
    fn writes_to_fd2_rejected() {
        let effs = vec![Effect::WriteF { fd: 2, bytes: b"CANARY".to_vec() }];
        assert!(matches!(
            check_trace(&effs, b"CANARY"),
            Err(InvariantError::UnauthorizedWrite(2))
        ));
    }
}
