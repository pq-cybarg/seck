# Threat model

## Adversary

- Supplies arbitrary file content (binary, malformed, adversarial Unicode).
- Has hyperscale GPU clusters.
- Has cryptanalytically-relevant quantum compute (defended by SHA3-256 + SLH-DSA / ML-DSA in Plan 07).
- Does NOT control the user's hardware, kernel, or display.

## In scope

| Threat | Defense | Verified by |
|---|---|---|
| Shell / command injection | Rust typestate (`Tainted<T>`) | 20 compile-fail tests |
| LLM prompt injection | Nonce-delimited region; capability denial; 3-pass (Plan 06) | red-team corpus |
| Parser RCEs (zip bombs, etc.) | Archives refused by default; size/count limits | `WalkLimits` |
| Network exfiltration | Empty netns; no socket calls allowed | sandbox-escape suite |
| Terminal-control injection | `seck-report::sanitize` strips ANSI/OSC/BiDi/ZWJ | 7 unit tests |
| Side channels in inference | `PR_SET_TSC=PR_TSC_SIGSEGV`, no `perf_event_open` | Plan 07 |
| Tampered binaries | SLH-DSA-signed releases | Plan 15 |
| Future SHA-2 / ECDSA break | SHA3-256 + PQ signatures (Plan 07) | Plan 07 KAT tests |

## Out of scope

- Cache-timing inherent to GEMM (documented; not mitigated).
- EM / power side channels.
- Kernel / hypervisor compromise.
- Adversarial control of the user's display.
- Full input-space verification of LLM semantics (computationally infeasible).
- Adversarial model weights chosen by the user without verifying the manifest signature.

## Plan 01 known limitations (some addressed in later plans)

- Single-pass LLM. Three-pass analyst/auditor/judge is Plan 06.
- llama.cpp backend only. Ollama/MLX are Plan 08.
- Linux runtime only on Plan 01. macOS sandbox added in Plan 02 (done).
- No PQ-signed releases yet; Plan 15 will add reproducible signed releases. Plan 07 (this plan, done) provides the SLH-DSA / ML-DSA primitives.
- Audit log added in Plan 07 (done).
- No archive extraction (refused by default; explicit opt-in is later).

## Plan 07 cryptographic posture (implemented)

| Algorithm | Use | Source |
|---|---|---|
| SHA3-256 (Keccak) | All hashing — file SHA, audit chain links, nonce commitments | `seck-crypto::hash` |
| SLH-DSA-SHAKE-128s (FIPS 205) | Release signatures (offline keys) | `seck-crypto::sign::slh_*` |
| ML-DSA-65 (FIPS 204) | Audit-log record signatures | `seck-crypto::sign::ml_dsa_*` |
| ML-KEM-768 (FIPS 203) | Reserved KEM slot (no network on the analysis path) | `seck-crypto::kem` |
| Argon2id (m≥512 MiB, t≥4, p≥4) | Memory-hard passphrase KDF | `seck-crypto::kdf` |
| AES-256-GCM-SIV / XChaCha20-Poly1305 | Symmetric AEAD where needed | `seck-crypto::sym` |

CI enforces "no SHA-2 in source" via `scripts/audit-no-sha2.sh`. The `--fips` runtime flag (`seck-crypto::fips::enable_fips()`) is a forward-looking gate that refuses any algorithm not on the NIST FIPS 203/204/205 allow-list — currently a no-op because every exposed primitive is already FIPS-aligned.
