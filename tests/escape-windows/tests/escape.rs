//! Plan-16 escape regressions. Each test runs the `escape_probe_windows`
//! bin with one probe; exit-code 2 means the probe succeeded and the
//! sandbox failed to deny.
#![cfg(target_os = "windows")]

use std::process::Command;

fn probe(name: &str) -> i32 {
    let bin = env!("CARGO_BIN_EXE_escape_probe_windows");
    let out = Command::new(bin)
        .arg(name)
        .output()
        .expect("spawn escape_probe_windows");
    out.status.code().unwrap_or(-1)
}

#[test]
fn cannot_open_sam_hive() {
    let code = probe("open_sam");
    assert_ne!(code, 2, "AppContainer should deny SAM hive read");
}

#[test]
#[ignore = "CIG only blocks NON-Microsoft-signed images; cmd.exe IS \
            Microsoft-signed and is allowed. The actual child-process \
            restriction comes from JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 1 \
            which is applied to the orchestrator-spawned child, not to \
            this in-process probe. Re-enable after wiring the Job \
            limit into apply_self_lockdown."]
fn cannot_spawn_cmd_exe() {
    let code = probe("spawn_cmd");
    assert_ne!(code, 2);
}

#[test]
fn cannot_create_socket() {
    let code = probe("socket");
    assert_ne!(code, 2, "AppContainer without internetClient should deny socket");
}

#[test]
fn cannot_open_winhello_db() {
    let code = probe("winhello");
    assert_ne!(code, 2, "AppContainer should deny Hello biometric DB read");
}
