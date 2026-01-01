//! `seck` — the user-facing CLI.

use anyhow::Context;
use clap::Parser;
use std::os::fd::FromRawFd;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "seck", version, about = "Sandboxed-LLM file/project analyzer")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Subcommand)]
enum Cmd {
    /// Analyze a file or directory inside a sandboxed LLM pipeline.
    Analyze(AnalyzeArgs),
}

#[derive(clap::Args)]
struct AnalyzeArgs {
    /// Path to analyze (file or directory). Mutually exclusive with --fd.
    #[arg(required_unless_present = "fd")]
    path: Option<PathBuf>,
    /// Read input from a pre-opened file descriptor inherited from the
    /// parent process (e.g., the macOS Seck.app applet or the Linux
    /// desktop portal). The path is NEVER passed as argv — only the FD.
    #[arg(long, conflicts_with = "path")]
    fd: Option<i32>,
    /// Sandbox mode. Plan 01-02 ship only mode 'a'.
    #[arg(long, default_value = "a")]
    sandbox_mode: String,
    /// Output format.
    #[arg(long, default_value = "json")]
    output: String,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Analyze(a) => analyze(a),
    }
}

fn analyze(args: AnalyzeArgs) -> anyhow::Result<()> {
    let entries = if let Some(raw_fd) = args.fd {
        // SAFETY: The CLI promises (and the macOS applet / Linux portal
        // ensure) that this FD was inherited from the parent and points
        // at a regular file opened with O_RDONLY|O_NOFOLLOW. We take
        // ownership of it via OwnedFd::from_raw_fd; the kernel will not
        // re-issue this FD to anyone else.
        #[allow(unsafe_code)]
        let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw_fd) };
        let size = match std::fs::metadata(format!("/dev/fd/{raw_fd}")) {
            Ok(m) => m.len(),
            Err(_) => 0,
        };
        vec![seck_host::walker::Entry {
            relative: PathBuf::from("fd_input"),
            fd: owned,
            size,
        }]
    } else {
        let path = args.path.as_ref().expect("required_unless_present");
        seck_host::walker::walk(path, Default::default())
            .with_context(|| format!("walking {path:?}"))?
    };
    let fileset = seck_host::fileset::build_fileset(entries).context("build fileset")?;

    let exe = std::env::current_exe()?;
    let reader = exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("can't locate seck-reader sibling"))?
        .join("seck-reader");
    if !reader.exists() {
        anyhow::bail!("seck-reader not found at {:?}", reader);
    }

    let result = seck_host::orchestrator::run_sandboxed(fileset, &reader)
        .context("running sandboxed reader")?;
    let v: serde_json::Value = serde_json::from_slice(&result.report_bytes)
        .context("parsing report JSON")?;
    if args.output == "json" {
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        let report: seck_report::schema::Report = serde_json::from_value(v)?;
        print!("{}", seck_report::renderer::render_terminal(&report));
    }
    let _ = args.sandbox_mode; // Plan 03+ adds more modes.
    Ok(())
}
