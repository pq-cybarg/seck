//! `seck tui <report>` — three-pane terminal UI viewer for a saved
//! JSON report.

use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct TuiArgs {
    pub report: PathBuf,
}

pub fn run(args: TuiArgs) -> anyhow::Result<()> {
    seck_tui::run(&args.report)
}
