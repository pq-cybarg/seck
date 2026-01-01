//! `seck audit init|verify|tip` subcommands.

use anyhow::{Context, anyhow};
use clap::{Args, Subcommand};
use rand::TryRngCore;
use std::path::PathBuf;

#[derive(Args)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub op: AuditOp,
}

#[derive(Subcommand)]
pub enum AuditOp {
    /// First-run setup: write a per-machine salt, derive the ML-DSA
    /// device keypair from a passphrase, write the public key.
    Init,
    /// Walk today's audit log (or `--day=YYYY-MM-DD`), verify every
    /// hash + signature, print the chain tip on success.
    Verify {
        #[arg(long)]
        day: Option<String>,
    },
    /// Print today's chain tip SHA3-256 without re-verifying.
    Tip,
}

fn xdg_dirs() -> (PathBuf, PathBuf) {
    let base = xdg::BaseDirectories::new().expect("XDG base dirs");
    let audit_dir = base
        .create_data_directory("seck/audit")
        .expect("xdg audit dir");
    let keys_dir = base
        .create_data_directory("seck/keys")
        .expect("xdg keys dir");
    (audit_dir, keys_dir)
}

pub fn run(args: AuditArgs) -> anyhow::Result<()> {
    let (audit_dir, keys_dir) = xdg_dirs();

    match args.op {
        AuditOp::Init => {
            let salt_path = keys_dir.join("salt.bin");
            let pk_path = keys_dir.join("device.pk");
            let sk_path = keys_dir.join("device.sk");
            if salt_path.exists() {
                anyhow::bail!(
                    "already initialized: {} exists (delete to re-init)",
                    salt_path.display()
                );
            }
            // 16-byte random salt.
            let mut salt = [0u8; 16];
            rand::rng()
                .try_fill_bytes(&mut salt)
                .context("CSPRNG fill")?;
            std::fs::write(&salt_path, salt).context("write salt")?;
            // Restrict perms on salt to 0600.
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&salt_path, std::fs::Permissions::from_mode(0o600))?;

            use std::io::Write;
            print!("Choose an audit-log passphrase (not echoed): ");
            std::io::stdout().flush()?;
            let pass = rpassword::read_password().context("read passphrase")?;
            if pass.is_empty() {
                anyhow::bail!("empty passphrase not allowed");
            }
            let key = seck_crypto::device_key::derive_device_key(pass.as_bytes(), &salt);
            std::fs::write(&pk_path, &key.public).context("write pk")?;
            std::fs::write(&sk_path, key.secret.as_slice()).context("write sk")?;
            std::fs::set_permissions(&sk_path, std::fs::Permissions::from_mode(0o600))?;
            std::fs::set_permissions(&pk_path, std::fs::Permissions::from_mode(0o644))?;
            println!("audit dir: {}", audit_dir.display());
            println!(
                "public key SHA3-256: {}",
                hex::encode(seck_crypto::hash::sha3_256(&key.public))
            );
            Ok(())
        }
        AuditOp::Verify { day } => {
            let pk = std::fs::read(keys_dir.join("device.pk"))
                .context("read public key (run 'seck audit init' first)")?;
            let day = day.unwrap_or_else(|| chrono::Utc::now().format("%Y-%m-%d").to_string());
            let path = audit_dir.join(format!("{day}.jsonl"));
            if !path.exists() {
                anyhow::bail!("no audit log for {day} at {}", path.display());
            }
            let tip =
                seck_audit::verify_chain(&path, &pk).map_err(|e| anyhow!("verify failed: {e}"))?;
            println!("OK — chain tip SHA3-256: {tip}");
            Ok(())
        }
        AuditOp::Tip => {
            let day = chrono::Utc::now().format("%Y-%m-%d");
            let path = audit_dir.join(format!("{day}.jsonl"));
            if !path.exists() {
                println!("(no log for today)");
                return Ok(());
            }
            let content = std::fs::read_to_string(&path)?;
            let tip = content
                .lines()
                .last()
                .and_then(|l| serde_json::from_str::<seck_audit::Record>(l).ok())
                .map(|r| r.this_sha3_256)
                .unwrap_or_else(|| "0".repeat(64));
            println!("{tip}");
            Ok(())
        }
    }
}
