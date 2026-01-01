// SandboxFd<Report> cannot be used where SandboxFd<Stdin> is required.
use std::os::fd::{FromRawFd, OwnedFd};
use seck_fd::{Report, SandboxFd, write_to_sandbox_pipe};
use seck_taint::Tainted;

fn main() {
    // SAFETY: This file is intended to fail to compile, so the unsafe block
    // is never reached at runtime.
    let fd: OwnedFd = unsafe { OwnedFd::from_raw_fd(1) };
    let report_fd: SandboxFd<Report> = SandboxFd::from_owned(fd);
    let t: Tainted<Vec<u8>> = Tainted::__new_internal(vec![1]);
    write_to_sandbox_pipe(t, &report_fd);
}
