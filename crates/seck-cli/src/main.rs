//! `seck` — the user-facing CLI.

use anyhow::Context;
use clap::Parser;
use std::os::fd::FromRawFd;
use std::path::PathBuf;

mod audit;
mod mcp;
mod models;
mod pair;
mod tui;
mod verify_proof;
mod web;

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
    /// Manage the per-machine audit log (init / verify / tip).
    Audit(audit::AuditArgs),
    /// Manage model files (Plan 07 ships only `verify`).
    Models(models::ModelsArgs),
    /// Run the MCP server over stdio (Plan 12).
    Mcp(mcp::McpArgs),
    /// Serve an HTML report locally (Plan 11).
    Web(web::WebArgs),
    /// Open a saved report in the terminal UI (Plan 10).
    Tui(tui::TuiArgs),
    /// Verify the Lean 4 proof of the IO-boundary theorem builds clean.
    VerifyProof,
    /// Pair a mobile share-target (Plan 17) via WireGuard-on-LAN.
    Pair(pair::PairArgs),
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
    /// (Windows) Read input from a pre-opened HANDLE inherited via
    /// `STARTUPINFOEXW` + `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`. Same role
    /// as `--fd` on Unix. The path never appears as argv.
    #[cfg(target_os = "windows")]
    #[arg(long, conflicts_with_all = &["path", "fd"])]
    handle: Option<u64>,
    /// Sandbox mode. Plan 01-02 ship only mode 'a'.
    #[arg(long, default_value = "a")]
    sandbox_mode: String,
    /// Output format.
    #[arg(long, default_value = "json")]
    output: String,
    /// Airgap mode (default ON): refuse any backend that opens a socket.
    #[arg(long, default_value_t = true)]
    airgap: bool,
    /// FIPS mode: constrain crypto to FIPS 203/204/205 parameter sets.
    #[arg(long, default_value_t = false)]
    fips: bool,
}

#[cfg(target_os = "linux")]
fn is_wsl2() -> bool {
    std::fs::read_to_string("/proc/version")
        .map(|s| s.contains("microsoft-standard") || s.contains("WSL2"))
        .unwrap_or(false)
}

#[cfg(not(target_os = "linux"))]
fn is_wsl2() -> bool {
    false
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    if is_wsl2() {
        tracing::info!("WSL2 detected; using Linux sandbox unchanged");
    }
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Analyze(a) => analyze(a),
        Cmd::Audit(a) => audit::run(a),
        Cmd::Models(a) => models::run(a),
        Cmd::Mcp(a) => mcp::run(a),
        Cmd::Web(a) => web::run(a),
        Cmd::Tui(a) => tui::run(a),
        Cmd::VerifyProof => verify_proof::run(),
        Cmd::Pair(a) => pair::run(a),
    }
}

fn analyze(args: AnalyzeArgs) -> anyhow::Result<()> {
    if args.fips {
        seck_crypto::fips::enable_fips();
    }
    if args.airgap {
        tracing::info!("--airgap on: network egress denied by sandbox");
    }

    let entries = if let Some(raw_fd) = args.fd {
        // SAFETY: The CLI promises (and the macOS applet / Linux portal
        // ensure) that this FD was inherited from the parent.
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
    let sib = exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("can't locate sibling binaries"))?;
    let reader = sib.join("seck-reader");
    if !reader.exists() {
        anyhow::bail!("seck-reader not found at {:?}", reader);
    }

    let result = match args.sandbox_mode.as_str() {
        "a" => seck_host::orchestrator::run_sandboxed(fileset, &reader)
            .context("running sandboxed reader (mode A)")?,
        "b" => {
            let reader_priv = sib.join("seck-reader-priv");
            if !reader_priv.exists() {
                anyhow::bail!("seck-reader-priv not found at {:?}", reader_priv);
            }
            seck_host::orchestrator::run_sandboxed_mode_b(fileset, &reader, &reader_priv)
                .context("running sandboxed reader (mode B)")?
        }
        other => anyhow::bail!("unknown --sandbox-mode: {other} (expected 'a' or 'b')"),
    };
    let v: serde_json::Value =
        serde_json::from_slice(&result.report_bytes).context("parsing report JSON")?;
    if args.output == "json" {
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        let report: seck_report::schema::Report = serde_json::from_value(v)?;
        print!("{}", seck_report::renderer::render_terminal(&report));
    }
    Ok(())
}
