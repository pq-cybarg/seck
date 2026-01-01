use crate::record::Record;
use serde_json::json;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct Writer {
    path: PathBuf,
    tip: String,
    sk: Vec<u8>,
}

impl Writer {
    /// Open (or create) today's audit log under `audit_dir/YYYY-MM-DD.jsonl`.
    /// Permissions are 0600. If the file exists, the writer resumes from
    /// the last record's chain tip.
    pub fn open(audit_dir: &Path, sk: Vec<u8>) -> std::io::Result<Self> {
        std::fs::create_dir_all(audit_dir)?;
        let day = chrono::Utc::now().format("%Y-%m-%d");
        let path = audit_dir.join(format!("{day}.jsonl"));
        let tip = if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            content
                .lines()
                .last()
                .and_then(|l| serde_json::from_str::<Record>(l).ok())
                .map(|r| r.this_sha3_256)
                .unwrap_or_else(|| "0".repeat(64))
        } else {
            "0".repeat(64)
        };

        // Create file if absent. Mode 0600 is enforced on Unix via
        // OpenOptionsExt; on Windows the audit log inherits the
        // user-profile ACL (the seck install runs single-user).
        if !path.exists() {
            let mut opts = std::fs::OpenOptions::new();
            opts.create(true).write(true).truncate(false);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            opts.open(&path)?;
        }
        Ok(Self { path, tip, sk })
    }

    pub fn tip(&self) -> &str {
        &self.tip
    }

    pub fn append(&mut self, event: &str, fields: BTreeMap<String, String>) -> std::io::Result<()> {
        let timestamp = chrono::Utc::now().to_rfc3339();
        let body = json!({
            "timestamp": &timestamp,
            "event": event,
            "fields": &fields,
            "prev_sha3_256": &self.tip,
        });
        let body_bytes = serde_json::to_vec(&body)?;
        let this_hash = hex::encode(seck_crypto::hash::sha3_256(&body_bytes));
        let sig = seck_crypto::sign::ml_dsa_sign(&self.sk, &body_bytes);
        let rec = Record {
            timestamp,
            event: event.into(),
            fields,
            prev_sha3_256: self.tip.clone(),
            this_sha3_256: this_hash.clone(),
            ml_dsa_signature_hex: hex::encode(sig),
        };
        let line = serde_json::to_string(&rec)? + "\n";
        let mut opts = std::fs::OpenOptions::new();
        opts.append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&self.path)?;
        f.write_all(line.as_bytes())?;
        self.tip = this_hash;
        Ok(())
    }
}
