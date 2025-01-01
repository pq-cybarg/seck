//! macOS Seatbelt-escape regression tests. Mirrors tests/escape on Linux.

#![cfg(target_os = "macos")]

use assert_cmd::Command;

fn check(kind: &str) {
    let bin = env!("CARGO_BIN_EXE_escape_probe_macos");
    let out = Command::new(bin).arg(kind).output().expect("ran probe");
    assert_ne!(
        out.status.code(),
        Some(2),
        "{kind}: Seatbelt FAILED — escape succeeded. stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn cannot_open_etc_hosts() {
    check("open_etc_hosts");
}

#[test]
fn cannot_list_etc_dir() {
    check("open_etc_dir");
}

#[test]
fn cannot_list_user_home() {
    check("open_user_dir");
}

// NOTE: bare socket(AF_INET, SOCK_STREAM, 0) creates a FD on macOS even
// under Seatbelt's `(deny network*)` — the kernel doesn't refuse the
// allocation, only the actual network operations on it. The
// cannot_tcp_connect test covers the operation that matters (no traffic
// can leave the sandbox). The Linux escape suite blocks socket() itself
// via seccomp.

#[test]
fn cannot_tcp_connect() {
    check("tcp_connect");
}

#[test]
fn cannot_write_to_tmp() {
    check("write_to_tmp");
}

#[test]
fn cannot_exec_sh() {
    check("exec_sh");
}
