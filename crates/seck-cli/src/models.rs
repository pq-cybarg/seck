//! `seck models verify <file> <sha3_256>` — Plan 09 stub. The full
//! manifest + downloader land in Plan 09; this subcommand alone is
//! enough for `--airgap` users who side-load GGUFs and want to confirm
//! they match a published hash.

use anyhow::Context;
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub struct ModelsArgs {
    #[command(subcommand)]
    pub op: ModelsOp,
}

#[derive(Subcommand)]
pub enum ModelsOp {
    /// Verify that a local file's SHA3-256 matches an expected value.
    /// Plan 09 adds list / pull / recommend.
    Verify {
        path: PathBuf,
        sha3_256_hex: String,
    },
}

pub fn run(args: ModelsArgs) -> anyhow::Result<()> {
    match args.op {
        ModelsOp::Verify {
            path,
            sha3_256_hex,
        } => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {path:?}"))?;
            let got = hex::encode(seck_crypto::hash::sha3_256(&bytes));
            let want = sha3_256_hex.to_lowercase();
            if got == want {
                println!("OK — {}", path.display());
                Ok(())
            } else {
                anyhow::bail!("sha3-256 mismatch: expected {want}, got {got}");
            }
        }
    }
}
