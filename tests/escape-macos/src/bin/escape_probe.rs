//! macOS Seatbelt-escape probe. Mirrors tests/escape on Linux.
//!
//! Exit codes:
//!   0 = escape was DENIED (sandbox held)
//!   2 = escape SUCCEEDED (regression)
//!   3 = bad argv / probe error

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("escape_probe_macos is macOS-only");
    std::process::exit(3);
}

#[cfg(target_os = "macos")]
fn main() {
    let kind = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!(
            "usage: escape_probe_macos <open_etc_master_passwd|open_libcorecrypto|open_keychain|tcp_connect|create_socket|write_to_tmp|exec_sh>"
        );
        std::process::exit(3);
    });

    let model_dir = std::path::PathBuf::from("/tmp");
    let infer_bin = std::path::PathBuf::from("/usr/bin/true");
    if let Err(e) = seck_sandbox::MacosSandbox::apply_self_lockdown(&model_dir, &infer_bin) {
        eprintln!("sandbox apply failed: {e}");
        std::process::exit(3);
    }

    let r: std::io::Result<()> = match kind.as_str() {
        // macOS doesn't have /etc/passwd as a sensitive file (it's a stub
        // on modern macOS). /etc/master.passwd is dscl-only/root-only and
        // we'd never get to read it. Use /etc/hosts which is world-readable
        // by default — if our sandbox blocks even this, we know file-read
        // restriction is active.
        "open_etc_hosts" => std::fs::File::open("/etc/hosts").map(|_| ()),
        "open_etc_dir" => std::fs::read_dir("/etc").map(|_| ()),
        "open_user_dir" => {
            let home = std::env::var("HOME").unwrap_or_default();
            std::fs::read_dir(home).map(|_| ())
        }
        "create_socket" => {
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            if fd < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
        "tcp_connect" => std::net::TcpStream::connect("127.0.0.1:1").map(|_| ()),
        "write_to_tmp" => std::fs::File::create("/tmp/seck-macos-escape-test").map(|_| ()),
        "exec_sh" => std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("true")
            .status()
            .map(|_| ()),
        other => {
            eprintln!("unknown escape kind: {other}");
            std::process::exit(3);
        }
    };

    if r.is_ok() {
        std::process::exit(2);
    }
    std::process::exit(0);
}
