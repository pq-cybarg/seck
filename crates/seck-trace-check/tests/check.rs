use seck_trace_check::{InvariantError, check_trace, parse_strace};

#[test]
fn flags_tainted_open() {
    let s = r#"openat(AT_FDCWD, "/etc/passwd-CANARY-xyz", O_RDONLY) = -1 ENOENT"#;
    let effs = parse_strace(s);
    let r = check_trace(&effs, b"CANARY-xyz");
    assert!(matches!(r, Err(InvariantError::TaintedOpen(_))));
}

#[test]
fn passes_tainted_write_to_fd3() {
    let s = r#"write(3, "CANARY-xyz contents", 19) = 19"#;
    let effs = parse_strace(s);
    let r = check_trace(&effs, b"CANARY-xyz");
    assert!(r.is_ok(), "fd 3 write of tainted bytes is allowed");
}

#[test]
fn passes_tainted_write_to_fd5() {
    let s = r#"write(5, "CANARY-xyz contents", 19) = 19"#;
    let effs = parse_strace(s);
    assert!(check_trace(&effs, b"CANARY-xyz").is_ok());
}

#[test]
fn flags_tainted_write_to_fd2() {
    let s = r#"write(2, "CANARY-xyz leaked", 17) = 17"#;
    let effs = parse_strace(s);
    let r = check_trace(&effs, b"CANARY-xyz");
    assert!(matches!(r, Err(InvariantError::UnauthorizedWrite(2))));
}

#[test]
fn flags_net_conn() {
    let s = r#"connect(7, {sa_family=AF_INET, sin_addr=inet_addr("1.2.3.4"), sin_port=htons(80)}, 16) = 0"#;
    let effs = parse_strace(s);
    let r = check_trace(&effs, b"any");
    assert!(matches!(r, Err(InvariantError::Net { .. })));
}

#[test]
fn untainted_open_ok() {
    let s = r#"openat(AT_FDCWD, "/usr/lib/libc.so.6", O_RDONLY) = 3"#;
    let effs = parse_strace(s);
    assert!(check_trace(&effs, b"CANARY-not-in-trace").is_ok());
}
