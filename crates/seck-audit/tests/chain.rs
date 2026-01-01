use seck_audit::{Writer, verify_chain};
use seck_crypto::sign::ml_dsa_keypair;
use std::collections::BTreeMap;
use tempfile::TempDir;

#[test]
fn write_then_verify() {
    let d = TempDir::new().unwrap();
    let (pk, sk) = ml_dsa_keypair();
    let mut w = Writer::open(d.path(), sk).unwrap();
    let mut f = BTreeMap::new();
    f.insert("nonce_sha3_256".into(), "abcd".into());
    w.append("analyze.start", f.clone()).unwrap();
    w.append("analyze.finish", f).unwrap();
    drop(w);
    let file = std::fs::read_dir(d.path()).unwrap().next().unwrap().unwrap().path();
    let tip = verify_chain(&file, &pk).unwrap();
    assert_eq!(tip.len(), 64);
}

#[test]
fn tampered_record_breaks_chain() {
    let d = TempDir::new().unwrap();
    let (pk, sk) = ml_dsa_keypair();
    let mut w = Writer::open(d.path(), sk).unwrap();
    w.append("test", BTreeMap::new()).unwrap();
    w.append("test2", BTreeMap::new()).unwrap();
    drop(w);
    let file = std::fs::read_dir(d.path()).unwrap().next().unwrap().unwrap().path();
    let content = std::fs::read_to_string(&file).unwrap();
    // Mutate any byte in the first record's event field.
    let tampered = content.replacen("\"event\":\"test\"", "\"event\":\"tampered\"", 1);
    std::fs::write(&file, tampered).unwrap();
    assert!(verify_chain(&file, &pk).is_err());
}

#[test]
fn empty_log_returns_genesis_tip() {
    let d = TempDir::new().unwrap();
    let (pk, _sk) = ml_dsa_keypair();
    // Create empty log file.
    let file = d.path().join(format!("{}.jsonl", chrono::Utc::now().format("%Y-%m-%d")));
    std::fs::write(&file, "").unwrap();
    let tip = verify_chain(&file, &pk).unwrap();
    assert_eq!(tip, "0".repeat(64));
}
