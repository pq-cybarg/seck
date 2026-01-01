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

## Layer 3 — Lean 4 machine-checked proof

`proof/` contains a Lean 4 Lake project that proves the IO-boundary
theorem: any program built from the host/reader models in
`proof/Seck/HostModel.lean` and `proof/Seck/ReaderModel.lean` produces a
`Trace` that satisfies `Trace.satisfiesIOBoundary`:

- `openP` paths are never tainted;
- `execP` paths, argv entries, and env entries are never tainted;
- the trace contains no `netConn` step;
- every `writeF` of tainted bytes goes to FD 3 (the sandbox stdin) or
  FD 5 (the report pipe).

`proof/Seck/IOBoundary.lean` discharges every case structurally or via
two audited correspondence axioms documented in
`proof/CORRESPONDENCE.md`. `lake build` succeeds with zero `sorry` /
`admit` in the load-bearing files — enforced both by
`.github/workflows/proof.yml` and by `seck verify-proof` locally.

The Lean proof shows the boundary holds *in the model*. The Rust
runtime side is audited by three independent enforcers, any one of
which would catch an implementation bypass:

1. Plan-01 Rust typestate (20 trybuild compile-fail cases on
   `Tainted<T>` conversions).
2. Plan-01 ptrace canary check (every CI run injects a per-run canary
   and asserts it never appears in argv/env/paths/sockets).
3. Plan-05 `seck-trace-check` (Rust analog of `Trace.checkIOBoundary`;
   parses real strace output, fuzz-driven by cargo-fuzz
   `trace_invariant`, wired into CI via
   `.github/workflows/trace-vs-model.yml`).

Approach B (Plan 04) adds a further compile-time guarantee enforced at
the workspace level: `crates/seck-reader-priv/` has no dependency on
`seck-taint`, so the type `Tainted<T>` is not even in scope in that
crate — `scripts/check-approach-b-invariant.sh` is the CI gate.
