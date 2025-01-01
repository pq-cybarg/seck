//! `seck models` — list / pull / verify / recommend.

use anyhow::Context;
use clap::{Args, Subcommand};
use std::path::PathBuf;

const BUNDLED_MANIFEST: &str =
    include_str!("../../../platform/manifests/models.manifest.toml");

#[derive(Args)]
pub struct ModelsArgs {
    #[command(subcommand)]
    pub op: ModelsOp,
}

#[derive(Subcommand)]
pub enum ModelsOp {
    /// List all entries from the bundled signed manifest.
    List,
    /// Recommend a model fitting the available RAM (--ram-gb).
    Recommend {
        #[arg(long, default_value_t = 16)]
        ram_gb: u32,
    },
    /// Download a model by name. Refuses in --airgap.
    Pull {
        name: String,
        #[arg(long, env = "SECK_AIRGAP", default_value_t = false)]
        airgap: bool,
    },
    /// Verify a local file's SHA3-256 against an expected hash.
    Verify {
        path: PathBuf,
        sha3_256_hex: String,
    },
}

pub fn run(args: ModelsArgs) -> anyhow::Result<()> {
    let manifest =
        seck_models::manifest::parse(BUNDLED_MANIFEST).context("parse bundled manifest")?;
    match args.op {
        ModelsOp::List => {
            for e in seck_models::recommend::list(&manifest) {
                println!(
                    "{:32}  {:>6.1}B  {:>4}GB  {}",
                    e.name, e.params_billion, e.recommended_min_ram_gb, e.license
                );
            }
            Ok(())
        }
        ModelsOp::Recommend { ram_gb } => {
            match seck_models::recommend::recommend_for_ram(&manifest, ram_gb) {
                Some(e) => {
                    println!(
                        "recommended: {} ({} GB RAM required, {:.1}B params, {})",
                        e.name, e.recommended_min_ram_gb, e.params_billion, e.license
                    );
                    Ok(())
                }
                None => anyhow::bail!("no model fits {ram_gb} GB RAM"),
            }
        }
        ModelsOp::Pull { name, airgap } => {
            if airgap {
                anyhow::bail!(
                    "--airgap on: pull refused. Side-load the GGUF and use 'seck models verify'."
                );
            }
            let entry = manifest
                .entries
                .iter()
                .find(|e| e.name == name)
                .ok_or_else(|| anyhow::anyhow!("no entry named '{name}' in bundled manifest"))?;
            let dest = seck_models::store::store_path(&entry.sha3_256, &entry.gguf_url);
            seck_host_net::download::download_verified(&entry.gguf_url, &entry.sha3_256, &dest)
                .with_context(|| format!("download {name}"))?;
            println!("OK — {} → {}", entry.name, dest.display());
            Ok(())
        }
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
