//! seck-verify-release: SLH-DSA verifies a binary against a signature.
//! Used by `scripts/install.sh` before installing a downloaded artifact.
//!
//! Exit codes: 0 = signature valid; 1 = invalid; 2 = io / args error.

use anyhow::Context;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    pubkey: PathBuf,
    #[arg(long)]
    binary: PathBuf,
    #[arg(long)]
    sig: PathBuf,
}

fn main() {
    if let Err(e) = real_main() {
        eprintln!("seck-verify-release: {e}");
        std::process::exit(2);
    }
}

fn real_main() -> anyhow::Result<()> {
    let a = Args::parse();
    let pk = std::fs::read(&a.pubkey).with_context(|| format!("read pubkey {:?}", a.pubkey))?;
    let msg = std::fs::read(&a.binary).with_context(|| format!("read binary {:?}", a.binary))?;
    let sig = std::fs::read(&a.sig).with_context(|| format!("read sig {:?}", a.sig))?;
    if seck_crypto::sign::slh_dsa_verify(&pk, &msg, &sig) {
        println!("OK");
        std::process::exit(0);
    } else {
        eprintln!("INVALID — SLH-DSA signature does not match");
        std::process::exit(1);
    }
}
