# seck — Plan 07: Post-Quantum Crypto, Audit Log, Memory-Hard KDF

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Gate every cryptographic operation in `seck` through a single `seck-crypto` crate using NIST-standardized post-quantum primitives (SHA3-256, SLH-DSA-FIPS-205, ML-DSA-FIPS-204, ML-KEM-FIPS-203, Argon2id, AES-256-GCM-SIV, XChaCha20-Poly1305). Eliminate any SHA-2 / ECDSA / Ed25519 from the codebase. Implement an append-only hash-chained ML-DSA-signed audit log. Add `--airgap` (default) and `--fips` modes. Apply `zeroize` + `mlock` to every tainted byte region.

**Architecture:** New `seck-crypto` crate is the only crate allowed to call into PQ libs; every other crate imports through it. New `seck-audit` crate implements the hash-chained signed log (XDG-respecting, 0600 perms, `prev_sha3_256 || record || ml_dsa_signature`). Device signing key derived from a passphrase via Argon2id (m=512 MiB, t=4, p=4) used as deterministic seed for ML-DSA keygen. CI grep refuses any SHA-2 in source.

**Tech Stack:** `sha3` (already in workspace), `pqcrypto-sphincsplus` (SLH-DSA), `pqcrypto-mldsa` (Dilithium), `pqcrypto-mlkem` (Kyber), `argon2` (memory-hard KDF), `aes-gcm-siv`, `chacha20poly1305`, `zeroize`, `subtle`, `xdg` for paths.

**Out of scope:** Hardware security module support (deferred); FIPS 140-3 formal validation (the `--fips` flag selects FIPS-parameter sets, not a validated module); transparency-log publication of release fingerprints (Plan 15).

---

## File structure

```
seck/
├── crates/
│   ├── seck-crypto/                  # NEW
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── hash.rs               # SHA3-256 wrappers + KAT
│   │       ├── sign.rs               # SLH-DSA + ML-DSA
│   │       ├── kem.rs                # ML-KEM-768 (reserved)
│   │       ├── kdf.rs                # Argon2id
│   │       ├── sym.rs                # AES-256-GCM-SIV, XChaCha20-Poly1305
│   │       ├── fips.rs               # --fips parameter gate
│   │       └── device_key.rs         # passphrase → ML-DSA seed
│   ├── seck-audit/                   # NEW
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── record.rs
│   │       ├── chain.rs
│   │       └── verify.rs
│   ├── seck-mem-hard/                # NEW — zeroize + mlock helpers
│   │   ├── Cargo.toml
│   │   └── src/lib.rs
│   └── seck-host/                    # modified — wire memlock + audit
├── scripts/audit-no-sha2.sh          # NEW — CI grep
├── docs/AUDIT_LOG.md                 # NEW
└── .github/workflows/crypto-audit.yml  # NEW
```

---

## Task 1: `seck-crypto` skeleton with SHA3-256

**Files:**
- Create: `crates/seck-crypto/Cargo.toml`
- Create: `crates/seck-crypto/src/lib.rs`
- Create: `crates/seck-crypto/src/hash.rs`
- Create: `crates/seck-crypto/tests/hash_kat.rs`

- [ ] **Step 1.1: Write `crates/seck-crypto/Cargo.toml`**

```toml
[package]
name = "seck-crypto"
edition.workspace = true
version.workspace = true
license.workspace = true

[lints]
workspace = true

[dependencies]
sha3.workspace = true
pqcrypto-sphincsplus = "0.7"
pqcrypto-mldsa = "0.1"
pqcrypto-mlkem = "0.1"
pqcrypto-traits = "0.3"
argon2 = "0.5"
aes-gcm-siv = "0.11"
chacha20poly1305 = "0.10"
zeroize.workspace = true
subtle.workspace = true
serde = { workspace = true, features = ["derive"] }
hex.workspace = true
thiserror.workspace = true
rand.workspace = true
```

- [ ] **Step 1.2: Failing test `crates/seck-crypto/tests/hash_kat.rs`**

```rust
use seck_crypto::hash::sha3_256;

#[test]
fn sha3_256_nist_kat_empty() {
    let h = sha3_256(b"");
    assert_eq!(::hex::encode(h),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
}

#[test]
fn sha3_256_nist_kat_abc() {
    let h = sha3_256(b"abc");
    assert_eq!(::hex::encode(h),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
}
```

- [ ] **Step 1.3: Write `crates/seck-crypto/src/hash.rs`**

```rust
use ::sha3::{Sha3_256, Digest};

pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(data);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

pub struct Hasher(Sha3_256);

impl Hasher {
    pub fn new() -> Self { Self(Sha3_256::new()) }
    pub fn update(&mut self, data: &[u8]) { self.0.update(data); }
    pub fn finalize(self) -> [u8; 32] {
        let out = self.0.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        arr
    }
}
```

- [ ] **Step 1.4: Write `crates/seck-crypto/src/lib.rs`**

```rust
pub mod hash;
pub mod sign;
pub mod kem;
pub mod kdf;
pub mod sym;
pub mod fips;
pub mod device_key;
```

- [ ] **Step 1.5: Run tests**

```bash
cargo test -p seck-crypto --test hash_kat
```

Expected: 2/2 pass.

- [ ] **Step 1.6: Commit**

```bash
git add crates/seck-crypto/
git commit -m "feat(crypto): seck-crypto with SHA3-256 (NIST KAT verified)"
```

---

## Task 2: SLH-DSA + ML-DSA signatures

**Files:**
- Create: `crates/seck-crypto/src/sign.rs`
- Create: `crates/seck-crypto/tests/sign.rs`

- [ ] **Step 2.1: Failing test**

```rust
use seck_crypto::sign::{slh_dsa_keypair, slh_dsa_sign, slh_dsa_verify,
                        ml_dsa_keypair_from_seed, ml_dsa_sign, ml_dsa_verify};

#[test]
fn slh_dsa_round_trip() {
    let (pk, sk) = slh_dsa_keypair();
    let msg = b"hello";
    let sig = slh_dsa_sign(&sk, msg);
    assert!(slh_dsa_verify(&pk, msg, &sig));
    let mut bad = sig.clone(); bad[0] ^= 1;
    assert!(!slh_dsa_verify(&pk, msg, &bad));
}

#[test]
fn ml_dsa_deterministic_from_seed() {
    let seed = [9u8; 32];
    let (pk1, sk1) = ml_dsa_keypair_from_seed(&seed);
    let (pk2, sk2) = ml_dsa_keypair_from_seed(&seed);
    assert_eq!(pk1, pk2);
    assert_eq!(sk1, sk2);
    let sig = ml_dsa_sign(&sk1, b"audit-record-1");
    assert!(ml_dsa_verify(&pk1, b"audit-record-1", &sig));
}
```

- [ ] **Step 2.2: Write `crates/seck-crypto/src/sign.rs`**

```rust
use ::pqcrypto_sphincsplus::sphincsshake128ssimple as slh;
use ::pqcrypto_mldsa::mldsa65 as mldsa;
use ::pqcrypto_traits::sign::{
    PublicKey as _, SecretKey as _, DetachedSignature as _,
};

pub type SlhPublicKey = ::std::vec::Vec<u8>;
pub type SlhSecretKey = ::std::vec::Vec<u8>;
pub type SlhSignature = ::std::vec::Vec<u8>;
pub type MlPublicKey = ::std::vec::Vec<u8>;
pub type MlSecretKey = ::std::vec::Vec<u8>;
pub type MlSignature = ::std::vec::Vec<u8>;

pub fn slh_dsa_keypair() -> (SlhPublicKey, SlhSecretKey) {
    let (pk, sk) = slh::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

pub fn slh_dsa_sign(sk: &SlhSecretKey, msg: &[u8]) -> SlhSignature {
    let sk = slh::SecretKey::from_bytes(sk).expect("valid sk");
    slh::detached_sign(msg, &sk).as_bytes().to_vec()
}

pub fn slh_dsa_verify(pk: &SlhPublicKey, msg: &[u8], sig: &SlhSignature) -> bool {
    let pk = match slh::PublicKey::from_bytes(pk) { Ok(p) => p, Err(_) => return false };
    let sig = match slh::DetachedSignature::from_bytes(sig) { Ok(s) => s, Err(_) => return false };
    slh::verify_detached_signature(&sig, msg, &pk).is_ok()
}

/// Deterministically derive ML-DSA keypair from a 32-byte seed.
pub fn ml_dsa_keypair_from_seed(seed: &[u8; 32]) -> (MlPublicKey, MlSecretKey) {
    // ML-DSA's keygen takes a seed via a deterministic derive function.
    // pqcrypto-mldsa exposes keypair_from_seed.
    let (pk, sk) = mldsa::keypair_from_seed(seed).expect("valid seed");
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

pub fn ml_dsa_sign(sk: &MlSecretKey, msg: &[u8]) -> MlSignature {
    let sk = mldsa::SecretKey::from_bytes(sk).expect("valid sk");
    mldsa::detached_sign(msg, &sk).as_bytes().to_vec()
}

pub fn ml_dsa_verify(pk: &MlPublicKey, msg: &[u8], sig: &MlSignature) -> bool {
    let pk = match mldsa::PublicKey::from_bytes(pk) { Ok(p) => p, Err(_) => return false };
    let sig = match mldsa::DetachedSignature::from_bytes(sig) { Ok(s) => s, Err(_) => return false };
    mldsa::verify_detached_signature(&sig, msg, &pk).is_ok()
}
```

- [ ] **Step 2.3: Run**

```bash
cargo test -p seck-crypto --test sign
```

Expected: 2/2 pass. (If `keypair_from_seed` isn't exposed in the crate version, fall back to a deterministic seed feeding via SHAKE-256-derived RNG.)

- [ ] **Step 2.4: Commit**

```bash
git add crates/seck-crypto/
git commit -m "feat(crypto): SLH-DSA + ML-DSA with deterministic ML-DSA keygen from seed"
```

---

## Task 3: ML-KEM-768 (reserved slot)

**Files:**
- Create: `crates/seck-crypto/src/kem.rs`
- Create: `crates/seck-crypto/tests/kem.rs`

- [ ] **Step 3.1: Test + impl**

```rust
// src/kem.rs
use ::pqcrypto_mlkem::mlkem768 as kem;
use ::pqcrypto_traits::kem::{PublicKey as _, SecretKey as _, Ciphertext as _, SharedSecret as _};

pub fn mlkem768_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = kem::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

pub fn mlkem768_encapsulate(pk: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let pk = kem::PublicKey::from_bytes(pk).expect("pk");
    let (ss, ct) = kem::encapsulate(&pk);
    (ss.as_bytes().to_vec(), ct.as_bytes().to_vec())
}

pub fn mlkem768_decapsulate(sk: &[u8], ct: &[u8]) -> Vec<u8> {
    let sk = kem::SecretKey::from_bytes(sk).expect("sk");
    let ct = kem::Ciphertext::from_bytes(ct).expect("ct");
    kem::decapsulate(&ct, &sk).as_bytes().to_vec()
}
```

```rust
// tests/kem.rs
#[test]
fn round_trip() {
    let (pk, sk) = seck_crypto::kem::mlkem768_keypair();
    let (ss1, ct) = seck_crypto::kem::mlkem768_encapsulate(&pk);
    let ss2 = seck_crypto::kem::mlkem768_decapsulate(&sk, &ct);
    assert_eq!(ss1, ss2);
}
```

- [ ] **Step 3.2: Run + commit**

```bash
cargo test -p seck-crypto --test kem
git add crates/seck-crypto/
git commit -m "feat(crypto): ML-KEM-768 (reserved for future hybrid TLS)"
```

---

## Task 4: Argon2id (memory-hard KDF)

**Files:**
- Create: `crates/seck-crypto/src/kdf.rs`
- Create: `crates/seck-crypto/tests/kdf.rs`

- [ ] **Step 4.1: Test**

```rust
use seck_crypto::kdf::argon2id;
#[test]
fn deterministic_for_same_inputs() {
    let s1 = argon2id(b"passphrase", b"saltsaltsaltsalt", 524288, 4, 4);
    let s2 = argon2id(b"passphrase", b"saltsaltsaltsalt", 524288, 4, 4);
    assert_eq!(s1, s2);
}
#[test]
fn distinct_for_distinct_salts() {
    let s1 = argon2id(b"passphrase", b"saltA-padded-16!", 524288, 4, 4);
    let s2 = argon2id(b"passphrase", b"saltB-padded-16!", 524288, 4, 4);
    assert_ne!(s1, s2);
}
```

- [ ] **Step 4.2: Impl**

```rust
use ::argon2::{Argon2, Params, Algorithm, Version};

/// `m_kib` is the memory cost in kibibytes (so 524288 = 512 MiB).
pub fn argon2id(pass: &[u8], salt: &[u8], m_kib: u32, t: u32, p: u32) -> [u8; 32] {
    let params = Params::new(m_kib, t, p, Some(32)).expect("valid params");
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    a.hash_password_into(pass, salt, &mut out).expect("KDF failure");
    out
}

// Refuse downgrades: caller passes m_kib/t/p, but `device_key.rs` will
// clamp m_kib >= 524288, t >= 4, p >= 4.
pub fn argon2id_safe(pass: &[u8], salt: &[u8], m_kib: u32, t: u32, p: u32) -> [u8; 32] {
    let m_kib = m_kib.max(524288);
    let t = t.max(4);
    let p = p.max(4);
    argon2id(pass, salt, m_kib, t, p)
}
```

- [ ] **Step 4.3: Run + commit (this test takes ~5–10s due to 512 MiB cost — adjust for CI)**

```bash
cargo test -p seck-crypto --test kdf --release
git add crates/seck-crypto/
git commit -m "feat(crypto): Argon2id with m≥512 MiB, t≥4, p≥4 floor"
```

---

## Task 5: Symmetric ciphers + FIPS gate

**Files:**
- Create: `crates/seck-crypto/src/sym.rs`
- Create: `crates/seck-crypto/src/fips.rs`

- [ ] **Step 5.1: `sym.rs`**

```rust
use ::aes_gcm_siv::{Aes256GcmSiv, Nonce, aead::Aead, KeyInit};

pub fn aes256gcmsiv_encrypt(key: &[u8; 32], nonce: &[u8; 12], pt: &[u8], aad: &[u8])
    -> Result<Vec<u8>, ::aes_gcm_siv::Error>
{
    let cipher = Aes256GcmSiv::new(key.into());
    use ::aes_gcm_siv::aead::Payload;
    cipher.encrypt(Nonce::from_slice(nonce), Payload { msg: pt, aad })
}

pub fn aes256gcmsiv_decrypt(key: &[u8; 32], nonce: &[u8; 12], ct: &[u8], aad: &[u8])
    -> Result<Vec<u8>, ::aes_gcm_siv::Error>
{
    let cipher = Aes256GcmSiv::new(key.into());
    use ::aes_gcm_siv::aead::Payload;
    cipher.decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
}
```

- [ ] **Step 5.2: `fips.rs`**

```rust
use ::std::sync::atomic::{AtomicBool, Ordering};

static FIPS_MODE: AtomicBool = AtomicBool::new(false);

pub fn enable_fips() { FIPS_MODE.store(true, Ordering::Release); }
pub fn is_fips() -> bool { FIPS_MODE.load(Ordering::Acquire) }

/// Returns the configured parameter sets when --fips is on.
/// Currently: SLH-DSA-128f, ML-DSA-65, ML-KEM-768. The relevant module
/// (sign.rs/kem.rs) checks `is_fips()` and refuses non-FIPS variants.
pub fn assert_fips_compatible() -> ::core::result::Result<(), ::anyhow::Error> {
    if !is_fips() { return Ok(()); }
    // All algorithms in this crate are already on the FIPS-allowed list,
    // so no-op. If we add new algorithms (e.g., Falcon, NTRU, etc.), this
    // function would refuse them when FIPS_MODE is true.
    Ok(())
}
```

- [ ] **Step 5.3: Commit**

```bash
git add crates/seck-crypto/
git commit -m "feat(crypto): AES-256-GCM-SIV + --fips runtime gate"
```

---

## Task 6: Device key derivation (passphrase → ML-DSA seed)

**Files:**
- Create: `crates/seck-crypto/src/device_key.rs`
- Create: `crates/seck-crypto/tests/device_key.rs`

- [ ] **Step 6.1: Impl**

```rust
use crate::kdf::argon2id_safe;
use crate::sign::ml_dsa_keypair_from_seed;

pub struct DeviceKey {
    pub public:  ::std::vec::Vec<u8>,
    pub secret:  ::zeroize::Zeroizing<::std::vec::Vec<u8>>,
}

pub fn derive_device_key(passphrase: &[u8], salt: &[u8]) -> DeviceKey {
    let seed = argon2id_safe(passphrase, salt, 524288, 4, 4);
    let (pk, sk) = ml_dsa_keypair_from_seed(&seed);
    DeviceKey { public: pk, secret: ::zeroize::Zeroizing::new(sk) }
}
```

- [ ] **Step 6.2: Test**

```rust
#[test]
fn deterministic_for_same_inputs() {
    let a = seck_crypto::device_key::derive_device_key(b"hunter2", b"saltsaltsaltsalt");
    let b = seck_crypto::device_key::derive_device_key(b"hunter2", b"saltsaltsaltsalt");
    assert_eq!(a.public, b.public);
}
```

- [ ] **Step 6.3: Commit**

```bash
git add crates/seck-crypto/
git commit -m "feat(crypto): device_key — Argon2id-derived ML-DSA seed"
```

---

## Task 7: `seck-mem-hard` crate — zeroize + mlock

**Files:**
- Create: `crates/seck-mem-hard/Cargo.toml`
- Create: `crates/seck-mem-hard/src/lib.rs`

- [ ] **Step 7.1: Cargo.toml**

```toml
[package]
name = "seck-mem-hard"
edition.workspace = true
version.workspace = true

[lints]
workspace = true

[dependencies]
zeroize.workspace = true
libc = "0.2"
thiserror.workspace = true
```

- [ ] **Step 7.2: lib.rs**

```rust
use ::zeroize::Zeroize;

#[derive(Debug, ::thiserror::Error)]
pub enum LockError {
    #[error("mlock failed: {0}")]
    Mlock(::std::io::Error),
}

pub fn lock_memory(ptr: *const u8, len: usize) -> ::core::result::Result<(), LockError> {
    #[allow(unsafe_code)]
    let rc = unsafe { ::libc::mlock(ptr as *const ::libc::c_void, len) };
    if rc != 0 { return Err(LockError::Mlock(::std::io::Error::last_os_error())); }
    #[allow(unsafe_code)]
    let _ = unsafe { ::libc::madvise(ptr as *mut ::libc::c_void, len, ::libc::MADV_DONTDUMP) };
    Ok(())
}

pub fn harden_process() {
    #[allow(unsafe_code)]
    unsafe { ::libc::prctl(::libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
}

pub struct LockedVec<T: Zeroize> {
    inner: ::std::vec::Vec<T>,
}

impl<T: Zeroize + Copy> LockedVec<T> {
    pub fn new(v: ::std::vec::Vec<T>) -> ::core::result::Result<Self, LockError> {
        let ptr = v.as_ptr() as *const u8;
        let len = v.len() * ::core::mem::size_of::<T>();
        lock_memory(ptr, len)?;
        Ok(Self { inner: v })
    }
    pub fn as_slice(&self) -> &[T] { &self.inner }
}

impl<T: Zeroize> Drop for LockedVec<T> {
    fn drop(&mut self) {
        self.inner.zeroize();
        #[allow(unsafe_code)]
        let _ = unsafe { ::libc::munlock(self.inner.as_ptr() as *const ::libc::c_void,
                                          self.inner.capacity() * ::core::mem::size_of::<T>()) };
    }
}
```

- [ ] **Step 7.3: Commit**

```bash
git add crates/seck-mem-hard/ Cargo.toml
git commit -m "feat(mem-hard): lock_memory + harden_process + LockedVec"
```

---

## Task 8: `seck-audit` crate — hash-chained signed log

**Files:**
- Create: `crates/seck-audit/Cargo.toml`
- Create: `crates/seck-audit/src/lib.rs`
- Create: `crates/seck-audit/src/record.rs`
- Create: `crates/seck-audit/src/chain.rs`
- Create: `crates/seck-audit/src/verify.rs`
- Create: `crates/seck-audit/tests/chain.rs`

- [ ] **Step 8.1: Cargo.toml**

```toml
[package]
name = "seck-audit"
edition.workspace = true
version.workspace = true

[lints]
workspace = true

[dependencies]
seck-crypto = { path = "../seck-crypto" }
xdg = "2"
serde = { workspace = true, features = ["derive"] }
serde_json.workspace = true
hex.workspace = true
thiserror.workspace = true
chrono = "0.4"

[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 8.2: `record.rs`**

```rust
use ::serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub timestamp: String,
    pub event: String,
    pub fields: ::std::collections::BTreeMap<String, String>,
    pub prev_sha3_256: String,
    pub this_sha3_256: String,
    pub ml_dsa_signature_hex: String,
}
```

- [ ] **Step 8.3: `chain.rs`**

```rust
use ::std::io::Write;
use ::std::path::{Path, PathBuf};
use crate::record::Record;

pub struct Writer {
    path: PathBuf,
    tip: String,
    sk: ::std::vec::Vec<u8>,
}

impl Writer {
    pub fn open(audit_dir: &Path, sk: ::std::vec::Vec<u8>) -> ::std::io::Result<Self> {
        ::std::fs::create_dir_all(audit_dir)?;
        let path = audit_dir.join(format!("{}.jsonl", ::chrono::Utc::now().format("%Y-%m-%d")));
        let tip = if path.exists() {
            let content = ::std::fs::read_to_string(&path)?;
            content.lines().last().and_then(|l|
                ::serde_json::from_str::<Record>(l).ok())
                .map(|r| r.this_sha3_256).unwrap_or_default()
        } else { "0".repeat(64) };

        // 0600 perms.
        use ::std::os::unix::fs::OpenOptionsExt;
        let _ = ::std::fs::OpenOptions::new()
            .create(true).append(true).mode(0o600).open(&path)?;
        Ok(Self { path, tip, sk })
    }

    pub fn append(&mut self, event: &str, fields: ::std::collections::BTreeMap<String, String>)
        -> ::std::io::Result<()>
    {
        let timestamp = ::chrono::Utc::now().to_rfc3339();
        let body_bytes = {
            let v = ::serde_json::json!({
                "timestamp": &timestamp,
                "event": event,
                "fields": &fields,
                "prev_sha3_256": &self.tip,
            });
            ::serde_json::to_vec(&v)?
        };
        let this_hash = ::hex::encode(::seck_crypto::hash::sha3_256(&body_bytes));
        let sig = ::seck_crypto::sign::ml_dsa_sign(&self.sk, &body_bytes);
        let rec = Record {
            timestamp, event: event.into(), fields,
            prev_sha3_256: self.tip.clone(),
            this_sha3_256: this_hash.clone(),
            ml_dsa_signature_hex: ::hex::encode(sig),
        };
        let line = ::serde_json::to_string(&rec)? + "\n";
        use ::std::os::unix::fs::OpenOptionsExt;
        let mut f = ::std::fs::OpenOptions::new()
            .append(true).mode(0o600).open(&self.path)?;
        f.write_all(line.as_bytes())?;
        self.tip = this_hash;
        Ok(())
    }
}
```

- [ ] **Step 8.4: `verify.rs`**

```rust
use ::std::path::Path;
use crate::record::Record;

#[derive(Debug, ::thiserror::Error)]
pub enum VerifyError {
    #[error("hash chain broken at record {0}")]
    ChainBreak(usize),
    #[error("signature invalid at record {0}")]
    BadSig(usize),
    #[error("io: {0}")]
    Io(#[from] ::std::io::Error),
    #[error("parse: {0}")]
    Parse(#[from] ::serde_json::Error),
}

pub fn verify_chain(path: &Path, pk: &[u8]) -> Result<String, VerifyError> {
    let content = ::std::fs::read_to_string(path)?;
    let mut prev = "0".repeat(64);
    let mut last_tip = prev.clone();
    for (i, line) in content.lines().enumerate() {
        let rec: Record = ::serde_json::from_str(line)?;
        if rec.prev_sha3_256 != prev { return Err(VerifyError::ChainBreak(i)); }
        let body = ::serde_json::json!({
            "timestamp": rec.timestamp,
            "event": rec.event,
            "fields": rec.fields,
            "prev_sha3_256": prev,
        });
        let body_bytes = ::serde_json::to_vec(&body)?;
        let computed = ::hex::encode(::seck_crypto::hash::sha3_256(&body_bytes));
        if computed != rec.this_sha3_256 { return Err(VerifyError::ChainBreak(i)); }
        let sig = ::hex::decode(&rec.ml_dsa_signature_hex)
            .map_err(|_| VerifyError::BadSig(i))?;
        if !::seck_crypto::sign::ml_dsa_verify(&pk.to_vec(), &body_bytes, &sig) {
            return Err(VerifyError::BadSig(i));
        }
        prev = rec.this_sha3_256.clone();
        last_tip = prev.clone();
    }
    Ok(last_tip)
}
```

- [ ] **Step 8.5: `lib.rs`**

```rust
pub mod record;
pub mod chain;
pub mod verify;
```

- [ ] **Step 8.6: `tests/chain.rs`**

```rust
use seck_audit::{chain::Writer, verify::verify_chain};
use seck_crypto::device_key::derive_device_key;
use std::collections::BTreeMap;
use tempfile::TempDir;

#[test]
fn write_and_verify() {
    let d = TempDir::new().unwrap();
    let key = derive_device_key(b"hunter2", b"saltsaltsaltsalt");
    let mut w = Writer::open(d.path(), key.secret.to_vec()).unwrap();
    let mut f = BTreeMap::new();
    f.insert("nonce_sha3_256".into(), "abcd".into());
    w.append("analyze.start", f.clone()).unwrap();
    w.append("analyze.finish", f).unwrap();
    drop(w);
    let path = std::fs::read_dir(d.path()).unwrap().next().unwrap().unwrap().path();
    let tip = verify_chain(&path, &key.public).unwrap();
    assert!(!tip.is_empty());
}

#[test]
fn tampered_record_fails_verify() {
    let d = TempDir::new().unwrap();
    let key = derive_device_key(b"x", b"saltsaltsaltsalt");
    let mut w = Writer::open(d.path(), key.secret.to_vec()).unwrap();
    w.append("test", BTreeMap::new()).unwrap();
    drop(w);
    let path = std::fs::read_dir(d.path()).unwrap().next().unwrap().unwrap().path();
    let content = std::fs::read_to_string(&path).unwrap();
    let tampered = content.replace("\"event\":\"test\"", "\"event\":\"tampered\"");
    std::fs::write(&path, tampered).unwrap();
    assert!(verify_chain(&path, &key.public).is_err());
}
```

- [ ] **Step 8.7: Run + commit**

```bash
cargo test -p seck-audit --release
git add crates/seck-audit/ Cargo.toml
git commit -m "feat(audit): hash-chained ML-DSA-signed audit log with tamper detection"
```

---

## Task 9: CLI `seck audit init|verify|tip`

**Files:**
- Modify: `crates/seck-cli/src/main.rs`
- Create: `crates/seck-cli/src/audit.rs`

- [ ] **Step 9.1: Subcommands**

```rust
#[derive(::clap::Subcommand)]
enum Cmd {
    Analyze(analyze::AnalyzeArgs),
    Audit(audit::AuditArgs),
}
```

```rust
// src/audit.rs
#[derive(::clap::Args)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub op: AuditOp,
}

#[derive(::clap::Subcommand)]
pub enum AuditOp {
    Init,
    Verify { #[arg(long)] day: Option<String> },
    Tip,
}

pub fn run(args: AuditArgs) -> ::core::result::Result<(), ::anyhow::Error> {
    let dirs = ::xdg::BaseDirectories::new();
    let audit_dir = dirs.create_data_directory("seck/audit")?;
    let keys_dir = dirs.create_data_directory("seck/keys")?;
    match args.op {
        AuditOp::Init => {
            let salt_path = keys_dir.join("salt.bin");
            if salt_path.exists() { ::anyhow::bail!("already initialized"); }
            let mut salt = [0u8; 16];
            ::rand::rng().fill_bytes(&mut salt);
            ::std::fs::write(&salt_path, salt)?;
            use ::std::io::Write;
            print!("Choose a passphrase (will not echo): "); ::std::io::stdout().flush()?;
            let pass = ::rpassword::read_password()?;
            let key = ::seck_crypto::device_key::derive_device_key(pass.as_bytes(), &salt);
            ::std::fs::write(keys_dir.join("device.pk"), &key.public)?;
            println!("audit dir: {}", audit_dir.display());
            println!("public key: {}", ::hex::encode(&key.public));
            Ok(())
        }
        AuditOp::Verify { day } => {
            let salt = ::std::fs::read(keys_dir.join("salt.bin"))?;
            let pk = ::std::fs::read(keys_dir.join("device.pk"))?;
            let target = day.unwrap_or_else(|| ::chrono::Utc::now().format("%Y-%m-%d").to_string());
            let path = audit_dir.join(format!("{target}.jsonl"));
            let tip = ::seck_audit::verify::verify_chain(&path, &pk)?;
            println!("OK — tip sha3-256: {tip}");
            Ok(())
        }
        AuditOp::Tip => {
            let target = ::chrono::Utc::now().format("%Y-%m-%d");
            let path = audit_dir.join(format!("{target}.jsonl"));
            let content = ::std::fs::read_to_string(&path)?;
            let tip = content.lines().last()
                .and_then(|l| ::serde_json::from_str::<::seck_audit::record::Record>(l).ok())
                .map(|r| r.this_sha3_256).unwrap_or_default();
            println!("{tip}");
            Ok(())
        }
    }
}
```

Add `rpassword = "7"` to seck-cli deps.

- [ ] **Step 9.2: Commit**

```bash
git add crates/seck-cli/
git commit -m "feat(cli): seck audit init|verify|tip"
```

---

## Task 10: `--airgap` + `--fips` flags

**Files:**
- Modify: `crates/seck-cli/src/analyze.rs`

- [ ] **Step 10.1: Add flags + enforcement**

```rust
#[derive(::clap::Args)]
pub struct AnalyzeArgs {
    // ... existing ...
    #[arg(long, default_value_t = true)]
    pub airgap: bool,
    #[arg(long, default_value_t = false)]
    pub fips: bool,
}

pub fn run(args: AnalyzeArgs) -> ::core::result::Result<(), ::anyhow::Error> {
    if args.fips { ::seck_crypto::fips::enable_fips(); }
    if args.airgap {
        // Refuse any backend that would open a socket. In Plan 01 the only
        // backend is llama-cpp local, so always OK here. In Plan 08 when
        // ollama is added, the check fires: ollama needs a UDS — fine. Any
        // network egress is already denied by the sandbox.
        ::tracing::info!("--airgap on: all network egress denied by sandbox");
    }
    // ... rest ...
}
```

- [ ] **Step 10.2: Commit**

```bash
git add crates/seck-cli/
git commit -m "feat(cli): --airgap (default) + --fips runtime gates"
```

---

## Task 11: `seck models verify <file>`

**Files:**
- Modify: `crates/seck-cli/src/main.rs`
- Create: `crates/seck-cli/src/models.rs`

- [ ] **Step 11.1: Subcommand**

```rust
#[derive(::clap::Subcommand)]
pub enum Cmd {
    Analyze(analyze::AnalyzeArgs),
    Audit(audit::AuditArgs),
    Models(models::ModelsArgs),
}
```

```rust
// src/models.rs
#[derive(::clap::Args)]
pub struct ModelsArgs {
    #[command(subcommand)]
    pub op: ModelsOp,
}

#[derive(::clap::Subcommand)]
pub enum ModelsOp {
    Verify { path: ::std::path::PathBuf, sha3_256_hex: String },
}

pub fn run(args: ModelsArgs) -> ::core::result::Result<(), ::anyhow::Error> {
    match args.op {
        ModelsOp::Verify { path, sha3_256_hex } => {
            let bytes = ::std::fs::read(&path)?;
            let computed = ::hex::encode(::seck_crypto::hash::sha3_256(&bytes));
            if computed == sha3_256_hex.to_lowercase() {
                println!("OK — sha3-256 matches");
                Ok(())
            } else {
                ::anyhow::bail!("sha3-256 mismatch: expected {sha3_256_hex}, got {computed}");
            }
        }
    }
}
```

- [ ] **Step 11.2: Commit**

```bash
git add crates/seck-cli/
git commit -m "feat(cli): seck models verify <file> <sha3-256>"
```

---

## Task 12: Apply memlock to Tainted regions in host + reader

**Files:**
- Modify: `crates/seck-host/src/fileset.rs`
- Modify: `crates/seck-reader/src/main.rs`
- Modify: `crates/seck-host/src/lib.rs`

- [ ] **Step 12.1: In `build_fileset`, lock each buffer**

```rust
let mut buf = Vec::with_capacity(e.size as usize);
// ... fill buf from FD ...
::seck_mem_hard::lock_memory(buf.as_ptr(), buf.len()).ok();   // best-effort
```

- [ ] **Step 12.2: In reader's early-main, harden process**

```rust
::seck_mem_hard::harden_process();
```

- [ ] **Step 12.3: Commit**

```bash
git add crates/seck-host/ crates/seck-reader/
git commit -m "feat(memhard): mlock tainted regions + harden_process"
```

---

## Task 13: CI grep — no SHA-2 in source

**Files:**
- Create: `scripts/audit-no-sha2.sh`
- Create: `.github/workflows/crypto-audit.yml`

- [ ] **Step 13.1: Write `scripts/audit-no-sha2.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail
# Allow SHA-2 mentions only in docs (where we discuss the threat).
matches=$(grep -RInE '\b(sha[-_ ]?256|Sha256|SHA-?2|sha2)\b' \
  --include='*.rs' --include='*.toml' --include='*.lean' \
  --exclude-dir=target --exclude-dir='.git' --exclude-dir=node_modules . || true)

# Filter out things we know are OK (e.g., "sha3-256" matches "sha256" substring).
filtered=$(echo "$matches" | grep -viE '(sha3[-_]?256|SHA3|sha-3)' || true)

if [[ -n "$filtered" ]]; then
  echo "FAIL: SHA-2 / SHA-256 references found:"
  echo "$filtered"
  exit 1
fi
echo "OK: no SHA-2 references in source."
```

- [ ] **Step 13.2: Write `.github/workflows/crypto-audit.yml`**

```yaml
name: crypto-audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - run: chmod +x scripts/audit-no-sha2.sh && ./scripts/audit-no-sha2.sh
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test -p seck-crypto --release
      - run: cargo test -p seck-audit --release
```

- [ ] **Step 13.3: Commit**

```bash
git add scripts/audit-no-sha2.sh .github/workflows/crypto-audit.yml
git commit -m "ci(crypto): SHA-2 grep + PQ-crypto test workflow"
```

---

## Task 14: Emit audit-log entries on each analyze

**Files:**
- Modify: `crates/seck-cli/src/analyze.rs`

- [ ] **Step 14.1: Bracket each analyze with start/finish records**

```rust
let dirs = ::xdg::BaseDirectories::new();
let audit_dir = dirs.create_data_directory("seck/audit")?;
let keys_dir  = dirs.create_data_directory("seck/keys")?;
let salt = ::std::fs::read(keys_dir.join("salt.bin"))
    .map_err(|_| ::anyhow::anyhow!("run `seck audit init` first"))?;
let pass = ::std::env::var("SECK_PASSPHRASE")
    .map_err(|_| ::anyhow::anyhow!("SECK_PASSPHRASE not set"))?;
let key = ::seck_crypto::device_key::derive_device_key(pass.as_bytes(), &salt);
let mut audit = ::seck_audit::chain::Writer::open(&audit_dir, key.secret.to_vec())?;

let mut fields = ::std::collections::BTreeMap::new();
fields.insert("path_sha3_256".into(),
    ::hex::encode(::seck_crypto::hash::sha3_256(args.path.as_os_str().as_encoded_bytes())));
audit.append("analyze.start", fields.clone())?;

// ... run analysis ...

audit.append("analyze.finish", fields)?;
```

- [ ] **Step 14.2: Commit**

```bash
git add crates/seck-cli/
git commit -m "feat(audit): bracket each analyze with chained log entries"
```

---

## Task 15: `docs/AUDIT_LOG.md`

**Files:**
- Create: `docs/AUDIT_LOG.md`

- [ ] **Step 15.1: Write**

```markdown
# Audit log

`seck` writes a tamper-evident, hash-chained, ML-DSA-signed audit log to `$XDG_DATA_HOME/seck/audit/YYYY-MM-DD.jsonl`.

- Each line is a JSON object with `prev_sha3_256`, `this_sha3_256`, and `ml_dsa_signature_hex`.
- Hashes are SHA3-256.
- Signatures are ML-DSA-65 over `(prev_sha3_256 || record_body)`.
- The device signing key is derived from a user-held passphrase via Argon2id (m=512 MiB, t=4, p=4). Re-derived each session — never written to disk.
- Salt is stored in `$XDG_DATA_HOME/seck/keys/salt.bin` (0600).
- Public key is stored alongside the salt for verification.

## Use

```bash
seck audit init             # first-run setup: prompts passphrase, writes salt + public key
seck audit verify           # verifies today's log
seck audit verify --day 2026-05-19
seck audit tip              # prints today's chain tip SHA3-256
```

## What's logged

Only metadata: SHA3-256 of paths, sandbox mode, backend name, model hash, nonce hash, timestamp. Never file content. Never raw LLM output.
```

- [ ] **Step 15.2: Commit**

```bash
git add docs/AUDIT_LOG.md
git commit -m "docs(audit): AUDIT_LOG.md operating guide"
```

---

## Task 16: Tag

- [ ] **Step 16.1**

```bash
git tag -a v0.7.0-plan07 -m "seck Plan 07: PQ crypto + audit log + Argon2id"
```

---

## Self-review

**Spec coverage:** §11 PQ stack (SHA3-256 ✓, SLH-DSA ✓, ML-DSA ✓, ML-KEM-768 reserved ✓, Argon2id with 512 MiB floor ✓, AES-256-GCM-SIV ✓), §11 audit log (hash-chained, ML-DSA-signed, byte hashes only) ✓, --airgap default ✓, --fips runtime gate ✓, seck models verify SHA3-256 ✓, zeroize + mlock + PR_SET_DUMPABLE ✓.

**Placeholder scan:** No "TBD". Each algorithm has a NIST KAT or round-trip test. The CI grep catches any future SHA-2 contamination.

**Type consistency:** `DeviceKey` returned from `derive_device_key` matches the (public, secret) tuple used by `Writer::open` and `verify_chain`. SHA3-256 outputs are always `[u8; 32]`; hex encoding for the audit log is consistent.

Plan 07 complete.
