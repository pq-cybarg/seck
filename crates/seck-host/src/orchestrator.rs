//! Spawn the sandboxed reader, write the FileSet onto its stdin pipe,
//! read its JSON report off the report pipe.

use crate::fileset::FileSet;
use nix::libc;
use seck_fd::{HostPipeFd, SandboxFd, Stdin, write_to_sandbox_pipe};
use seck_proto::{MAGIC_HEADER, MAGIC_TRAILER, VERSION};
use seck_taint::Tainted;

#[derive(Debug, thiserror::Error)]
pub enum OrchestratorError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("nix: {0}")]
    Nix(#[from] nix::Error),
    #[error("fd: {0}")]
    Fd(#[from] seck_fd::FdError),
    #[error("reader exited with non-zero status")]
    ReaderFailed,
    #[error("sandbox setup: {0}")]
    Sandbox(String),
}

pub struct OrchestratorResult {
    pub report_bytes: Vec<u8>,
}

/// Spawn the reader binary in a child process; pass the FileSet on its
/// stdin (FD 3); collect the report on FD 5. The reader applies the
/// sandbox to itself in its main(); on macOS the stub sandbox returns an
/// error so the reader exits non-zero (expected until Plan 02 lands).
pub fn run_sandboxed(
    fileset: FileSet,
    reader_binary: &std::path::Path,
) -> Result<OrchestratorResult, OrchestratorError> {
    let (stdin_r, stdin_w) = nix::unistd::pipe()?;
    let (report_r, report_w) = nix::unistd::pipe()?;

    // Set up the child via std::process::Command + pre_exec for FD dup.
    use std::os::fd::AsRawFd;
    let stdin_r_raw = stdin_r.as_raw_fd();
    let report_w_raw = report_w.as_raw_fd();
    let mut cmd = std::process::Command::new(reader_binary);
    cmd.arg("--protocol-version=1").env_clear().env("LANG", "C");
    use std::os::unix::process::CommandExt;
    // SAFETY: pre_exec runs in the child after fork() and before execvp().
    // dup2(2) is async-signal-safe. We use raw libc::dup2 because nix's
    // dup2_raw requires AsFd which we can't satisfy from raw i32 in a
    // 'static closure.
    #[allow(unsafe_code)]
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(stdin_r_raw, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::dup2(report_w_raw, 5) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = cmd.spawn()?;

    // Close child ends in the parent.
    drop(stdin_r);
    drop(report_w);

    // Wrap parent ends in capability types.
    let sandbox_stdin = SandboxFd::<Stdin>::from_owned(stdin_w);
    let report_fd: HostPipeFd<()> = HostPipeFd::from_owned(report_r);

    write_fileset_protocol(&sandbox_stdin, fileset)?;
    // Closing the stdin FD signals EOF to the reader.
    drop(sandbox_stdin);

    let mut report = Vec::new();
    read_to_end_from_fd(&report_fd, &mut report)?;

    let status = child.wait()?;
    if !status.success() {
        return Err(OrchestratorError::ReaderFailed);
    }
    Ok(OrchestratorResult { report_bytes: report })
}

fn write_fileset_protocol(
    fd: &SandboxFd<Stdin>,
    fileset: FileSet,
) -> Result<(), OrchestratorError> {
    let entries = fileset.into_entries();

    // Header.
    let mut header = Vec::with_capacity(12);
    header.extend_from_slice(MAGIC_HEADER);
    header.extend_from_slice(&VERSION.to_le_bytes());
    header.extend_from_slice(&[0u8; 2]);
    header.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    write_to_sandbox_pipe(Tainted::__new_internal(header), fd)?;

    for entry in entries {
        let rel = entry
            .relative
            .into_inner()
            .to_string_lossy()
            .into_owned()
            .into_bytes();
        let mut framing = Vec::with_capacity(12 + rel.len());
        framing.extend_from_slice(&(rel.len() as u32).to_le_bytes());
        framing.extend_from_slice(&rel);
        framing.extend_from_slice(&entry.size.to_le_bytes());
        write_to_sandbox_pipe(Tainted::__new_internal(framing), fd)?;
        write_to_sandbox_pipe(entry.bytes, fd)?;
    }

    let trailer = Vec::from(MAGIC_TRAILER);
    write_to_sandbox_pipe(Tainted::__new_internal(trailer), fd)?;
    Ok(())
}

fn read_to_end_from_fd<Tag>(
    fd: &HostPipeFd<Tag>,
    out: &mut Vec<u8>,
) -> Result<(), OrchestratorError> {
    let mut buf = [0u8; 8192];
    loop {
        let n = nix::unistd::read(fd.as_fd(), &mut buf)?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(())
}

/// Approach B: two-process capability split.
///
/// - `reader_bytes_binary` (typically `seck-reader --mode=bytes-to-ipc`)
///   sees the raw bytes from FD 3, base64-encodes them, and emits a
///   line-delimited IPC stream on FD 7.
/// - `reader_priv_binary` (the `seck-reader-priv` bin) consumes the IPC
///   on its FD 3 and writes the report on FD 5. It has NO dependency on
///   `seck-taint`; the type `Tainted<Vec<u8>>` is not even in scope, so
///   it cannot be constructed there in principle.
///
/// CI gate `scripts/check-approach-b-invariant.sh` enforces the no-dep
/// rule at the workspace level.
///
/// Pipe topology:
///
/// ```text
///   host ──FileSet──▶ bytes(FD 3)
///                      bytes(FD 7) ──IPC msgs──▶ priv(FD 3)
///                                                  priv(FD 5) ──report──▶ host
/// ```
pub fn run_sandboxed_mode_b(
    fileset: FileSet,
    reader_bytes_binary: &std::path::Path,
    reader_priv_binary: &std::path::Path,
) -> Result<OrchestratorResult, OrchestratorError> {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;

    // Three pipes; the parent will write to (host_to_bytes_w) and read
    // from (priv_to_host_r).
    let (host_to_bytes_r, host_to_bytes_w) = nix::unistd::pipe()?;
    let (bytes_to_priv_r, bytes_to_priv_w) = nix::unistd::pipe()?;
    let (priv_to_host_r, priv_to_host_w) = nix::unistd::pipe()?;

    // Raw fds for pre_exec closures (they must be Copy + 'static).
    let h2b_r = host_to_bytes_r.as_raw_fd();
    let b2p_r = bytes_to_priv_r.as_raw_fd();
    let b2p_w = bytes_to_priv_w.as_raw_fd();
    let p2h_w = priv_to_host_w.as_raw_fd();

    // ---- spawn bytes (the bytes-to-ipc reader) ----
    let mut bytes_cmd = std::process::Command::new(reader_bytes_binary);
    bytes_cmd
        .arg("--protocol-version=1")
        .arg("--mode=bytes-to-ipc")
        .env_clear()
        .env("LANG", "C");
    // SAFETY: pre_exec runs in the child after fork() and before execvp.
    // dup2/close are async-signal-safe.
    #[allow(unsafe_code)]
    unsafe {
        bytes_cmd.pre_exec(move || {
            if libc::dup2(h2b_r, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::dup2(b2p_w, 7) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut bytes_child = bytes_cmd.spawn()?;

    // ---- spawn priv (the inference orchestrator) ----
    let mut priv_cmd = std::process::Command::new(reader_priv_binary);
    priv_cmd.env_clear().env("LANG", "C");
    if let Ok(model) = std::env::var("SECK_MODEL_PATH") {
        priv_cmd.env("SECK_MODEL_PATH", model);
    }
    #[allow(unsafe_code)]
    unsafe {
        priv_cmd.pre_exec(move || {
            if libc::dup2(b2p_r, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::dup2(p2h_w, 5) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut priv_child = priv_cmd.spawn()?;

    // The parent must drop every fd that lives in a child, otherwise no
    // EOF will ever propagate.
    drop(host_to_bytes_r);
    drop(bytes_to_priv_r);
    drop(bytes_to_priv_w);
    drop(priv_to_host_w);

    // Host now owns: host_to_bytes_w (write) and priv_to_host_r (read).
    let sandbox_stdin = SandboxFd::<Stdin>::from_owned(host_to_bytes_w);
    let report_fd: HostPipeFd<()> = HostPipeFd::from_owned(priv_to_host_r);

    write_fileset_protocol(&sandbox_stdin, fileset)?;
    drop(sandbox_stdin);

    let mut report = Vec::new();
    read_to_end_from_fd(&report_fd, &mut report)?;

    let bytes_status = bytes_child.wait()?;
    let priv_status = priv_child.wait()?;
    if !bytes_status.success() || !priv_status.success() {
        return Err(OrchestratorError::ReaderFailed);
    }
    Ok(OrchestratorResult { report_bytes: report })
}
