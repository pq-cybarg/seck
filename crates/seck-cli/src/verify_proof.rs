//! `seck verify-proof` — run `lake build` on the bundled Lean 4 proof
//! tree under `proof/` and report success/failure. Used as a local
//! sanity check by developers; CI runs the same step via
//! `.github/workflows/proof.yml`.

use std::process::Command;

pub fn run() -> anyhow::Result<()> {
    // Walk up from the binary to find a `proof/` sibling.
    let exe = std::env::current_exe()?;
    let mut probe = exe.as_path();
    let proof_dir = loop {
        match probe.parent() {
            Some(p) => {
                let cand = p.join("proof");
                if cand.join("lakefile.toml").is_file() {
                    break cand;
                }
                probe = p;
            }
            None => anyhow::bail!("could not locate proof/ from {exe:?}"),
        }
    };

    let out = Command::new("lake")
        .args(["build"])
        .current_dir(&proof_dir)
        .output()
        .map_err(|e| anyhow::anyhow!("failed to spawn lake (is elan installed?): {e}"))?;
    if !out.status.success() {
        anyhow::bail!(
            "lake build failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    // Forbid sorry/admit in the load-bearing files.
    for rel in [
        "Seck/IOBoundary.lean",
        "Seck/Correspondence.lean",
        "Seck/HostModel.lean",
        "Seck/ReaderModel.lean",
    ] {
        let p = proof_dir.join(rel);
        let body = std::fs::read_to_string(&p)?;
        for (lineno, line) in body.lines().enumerate() {
            let trimmed = line.trim_start();
            // Skip comment-only mentions
            if trimmed.starts_with("--") {
                continue;
            }
            if line.contains("sorry") || line.contains("admit") {
                anyhow::bail!(
                    "{}:{}: load-bearing proof file contains sorry/admit",
                    p.display(),
                    lineno + 1
                );
            }
        }
    }
    println!("IO-boundary proof builds (no sorry/admit in load-bearing files).");
    Ok(())
}
