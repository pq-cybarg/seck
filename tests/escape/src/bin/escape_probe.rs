//! Standalone escape probe. Applies seck-sandbox::LinuxSandbox to itself,
//! then attempts one of several known escape vectors selected via argv[1].
//!
//! Exit codes:
//!   0 = the escape was DENIED (expected; sandbox held)
//!   2 = the escape SUCCEEDED (regression; sandbox failed)
//!   3 = bad argv / probe error
//!
//! In addition, a successful sandbox often kills the process with SIGSYS or
//! similar from seccomp / Landlock — the test wrapper treats any non-2
//! exit as a pass.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("escape_probe is Linux-only");
    std::process::exit(3);
}

#[cfg(target_os = "linux")]
fn main() {
    let kind = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: escape_probe <open_passwd|open_shadow|open_etc_dir|landlock_status>");
        std::process::exit(3);
    });

    if let Err(e) = seck_sandbox::LinuxSandbox::apply_self_lockdown() {
        eprintln!("lockdown failed: {e}");
        std::process::exit(3);
    }

    let r: std::io::Result<()> = match kind.as_str() {
        "open_passwd" => std::fs::File::open("/etc/passwd").map(|_| ()),
        "open_shadow" => std::fs::File::open("/etc/shadow").map(|_| ()),
        "open_etc_dir" => std::fs::read_dir("/etc").map(|_| ()),
        "open_home_dotssh" => {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
            std::fs::read_dir(format!("{home}/.ssh")).map(|_| ())
        }
        "open_proc_self_environ" => std::fs::File::open("/proc/self/environ").map(|_| ()),
        "open_tmp_for_write" => std::fs::File::create("/tmp/seck-escape-test").map(|_| ()),
        "landlock_status" => {
            // Diagnostic only: print whether we can still see /tmp listing.
            // Exits 0 regardless.
            let _ = std::fs::read_dir("/tmp");
            Ok(())
        }
        other => {
            eprintln!("unknown escape kind: {other}");
            std::process::exit(3);
        }
    };

    if r.is_ok() {
        // The operation succeeded — escape was NOT blocked.
        std::process::exit(2);
    }
    // Failure (EACCES, EPERM, ENOENT-from-landlock, etc.) — expected.
    std::process::exit(0);
}
