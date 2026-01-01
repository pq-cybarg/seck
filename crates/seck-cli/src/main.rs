//! `seck` — the user-facing CLI. Plan 01 implements only `seck analyze`.

use anyhow::Context;
use clap::Parser;
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
    /// Path to analyze (file or directory).
    path: PathBuf,
    /// Sandbox mode. Plan 01 ships only 'a'.
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
    let entries = seck_host::walker::walk(&args.path, Default::default())
        .with_context(|| format!("walking {:?}", args.path))?;
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
        // Human renderer goes through the sanitizer.
        let report: seck_report::schema::Report = serde_json::from_value(v)?;
        print!("{}", seck_report::renderer::render_terminal(&report));
    }
    let _ = args.sandbox_mode; // Plan 03+ adds more modes.
    Ok(())
}
