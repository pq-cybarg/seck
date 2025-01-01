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

## Plan 01 (this MVP) — known limitations

- Single-pass LLM. Three-pass analyst/auditor/judge is Plan 06.
- llama.cpp backend only. Ollama/MLX are Plan 08.
- Linux runtime only. macOS sandbox is Plan 02.
- No PQ-signed releases. Plan 07 + Plan 15.
- No audit log. Plan 07.
- No archive extraction (refused by default; explicit opt-in is later).

Each item is addressed by a later plan.
