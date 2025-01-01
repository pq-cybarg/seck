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
