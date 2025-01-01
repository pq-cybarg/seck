//! Sandbox-escape regression tests. Each test invokes the `escape_probe`
//! binary with a single argv, which applies the sandbox and then attempts
//! one escape vector. Exit code 2 from the probe = the escape succeeded
//! (sandbox failed). Any other exit = denial / signal kill = pass.

#![cfg(target_os = "linux")]

use assert_cmd::Command;

fn check(kind: &str) {
    let bin = env!("CARGO_BIN_EXE_escape_probe");
    let out = Command::new(bin)
        .arg(kind)
        .output()
        .expect("ran probe");
    assert_ne!(
        out.status.code(),
        Some(2),
        "{kind}: sandbox FAILED — escape succeeded. stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn cannot_open_etc_passwd() {
    check("open_passwd");
}

#[test]
fn cannot_open_etc_shadow() {
    check("open_shadow");
}

#[test]
fn cannot_list_etc_dir() {
    check("open_etc_dir");
}

#[test]
fn cannot_open_home_dotssh() {
    check("open_home_dotssh");
}

#[test]
fn cannot_open_proc_self_environ() {
    check("open_proc_self_environ");
}

#[test]
fn cannot_write_to_tmp() {
    check("open_tmp_for_write");
}
