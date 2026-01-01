//! `seck web --bind=127.0.0.1:0 <report.json>` — server-rendered HTML
//! report, loopback only, single-use token.

use anyhow::Context;
use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct WebArgs {
    /// Loopback address to bind. Defaults to `127.0.0.1:0` (ephemeral).
    #[arg(long, default_value = "127.0.0.1:0")]
    pub bind: String,
    /// Path to a previously-saved JSON report.
    pub report: PathBuf,
}

pub fn run(args: WebArgs) -> anyhow::Result<()> {
    let addr = seck_web::resolve_bind(&args.bind).with_context(|| format!("bind {}", args.bind))?;
    let bytes = std::fs::read(&args.report).with_context(|| format!("read {:?}", args.report))?;
    let report: seck_report::schema::Report = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse JSON report from {:?}", args.report))?;
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(seck_web::serve(addr, report))
}
