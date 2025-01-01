//! Plan-16 escape probes. Each subcommand attempts one capability that
//! the AppContainer + mitigation cascade is supposed to deny. Exits 2
//! on success (= sandbox FAILED to deny), 1 on the expected error.
#![cfg(target_os = "windows")]

use std::process::ExitCode;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Storage::FileSystem::*;

fn main() -> ExitCode {
    let arg = std::env::args().nth(1).unwrap_or_default();

    if let Err(e) = seck_sandbox::WindowsSandbox::apply_self_lockdown() {
        eprintln!("escape_probe_windows: lockdown failed: {e}");
        // Returning 1 (not 2) — we couldn't even apply the sandbox.
        return ExitCode::from(1);
    }

    let r = match arg.as_str() {
        "open_sam" => probe_open(r"C:\Windows\System32\config\SAM"),
        "spawn_cmd" => probe_spawn(r"C:\Windows\System32\cmd.exe"),
        "socket" => probe_socket(),
        "winhello" => probe_open(r"C:\Windows\System32\WinBio\Hello"),
        other => {
            eprintln!("unknown probe: {other}");
            return ExitCode::from(1);
        }
    };
    if r.is_ok() {
        eprintln!("escape_probe_windows: PROBE SUCCEEDED — sandbox FAILED");
        ExitCode::from(2)
    } else {
        eprintln!("escape_probe_windows: denied as expected");
        ExitCode::from(1)
    }
}

fn probe_open(path: &str) -> std::io::Result<()> {
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let h = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            core::ptr::null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            core::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        Err(std::io::Error::last_os_error())
    } else {
        unsafe { CloseHandle(h) };
        Ok(())
    }
}

fn probe_spawn(_path: &str) -> std::io::Result<()> {
    // CreateProcessW would attempt to launch cmd.exe; under CIG this is
    // expected to fail because cmd.exe is not signed by Microsoft *for
    // the AppContainer's child-process allow-list*. We simulate by
    // trying to launch it via std::process::Command and translating
    // success into Ok (= bad).
    std::process::Command::new("cmd.exe").arg("/c").arg("exit").spawn().map(|_| ())
}

fn probe_socket() -> std::io::Result<()> {
    // Under AppContainer without the `internetClient` capability,
    // socket() should fail; but creating a raw SOCKET via WinSock from
    // a non-WSAStartup'd process also fails. Use `TcpStream::connect`
    // which exercises both layers.
    std::net::TcpStream::connect("127.0.0.1:1").map(|_| ())
}
