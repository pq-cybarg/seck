//! `cargo run -p seck-release-sign --example gen_release_key -- <pk-path> <sk-path>`
//! Generates an SLH-DSA-SHAKE-128s keypair, writes the pubkey to pk-path
//! and the secret key to sk-path (0600). Intended for air-gapped use.

fn main() {
    let mut args = std::env::args().skip(1);
    let pk_path = args.next().expect("usage: gen_release_key <pk> <sk>");
    let sk_path = args.next().expect("usage: gen_release_key <pk> <sk>");
    let (pk, sk) = seck_crypto::sign::slh_dsa_keypair();
    std::fs::write(&pk_path, &pk).unwrap();
    std::fs::write(&sk_path, &sk).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sk_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    println!(
        "wrote {pk_path} ({} bytes) and {sk_path} ({} bytes, 0600)",
        pk.len(),
        sk.len()
    );
    println!("SHA3-256(pk) = {}", hex::encode(seck_crypto::hash::sha3_256(&pk)));
}
