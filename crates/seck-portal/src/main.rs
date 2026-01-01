//! seck-portal: DBus session-bus service that owns the FD handoff for
//! Linux desktop integrations. The .desktop / Nautilus / KDE / Thunar
//! menu entries call `net.seck.Analyze.AnalyzePath(path: s)` which lands
//! HERE — we open the path on the seck side with O_NOFOLLOW, then
//! `seck analyze --fd=N` with the FD inherited. The PATH never reaches
//! seck's argv.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("seck-portal is Linux-only.");
    std::process::exit(0);
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use tokio::runtime::Runtime;
    let rt = Runtime::new()?;
    rt.block_on(server::run())
}

#[cfg(target_os = "linux")]
mod server {
    use std::os::fd::IntoRawFd;
    use std::os::unix::process::CommandExt;
    use zbus::interface;

    pub struct AnalyzeService;

    #[interface(name = "net.seck.Analyze")]
    impl AnalyzeService {
        async fn analyze_path(&mut self, path: String) -> zbus::fdo::Result<()> {
            let p = std::path::Path::new(&path);
            let fd = seck_host_unsafe::open_target(p)
                .map_err(|e| zbus::fdo::Error::Failed(format!("{e}")))?;
            let raw = fd.into_raw_fd();
            let exe = which("seck").unwrap_or_else(|| "/usr/local/bin/seck".into());
            let mut cmd = std::process::Command::new(exe);
            cmd.arg("analyze").arg("--fd=3");
            // SAFETY: dup2 is async-signal-safe.
            #[allow(unsafe_code)]
            unsafe {
                cmd.pre_exec(move || {
                    if libc::dup2(raw, 3) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            cmd.spawn()
                .map_err(|e| zbus::fdo::Error::Failed(format!("{e}")))?;
            Ok(())
        }
    }

    fn which(prog: &str) -> Option<std::path::PathBuf> {
        std::env::var("PATH").ok().and_then(|p| {
            std::env::split_paths(&p)
                .map(|d| d.join(prog))
                .find(|c| c.is_file())
        })
    }

    pub async fn run() -> anyhow::Result<()> {
        let _conn = zbus::connection::Builder::session()?
            .name("net.seck.Analyze")?
            .serve_at("/net/seck/Analyze", AnalyzeService)?
            .build()
            .await?;
        // Keep the bus connection alive.
        std::future::pending::<()>().await;
        Ok(())
    }
}
