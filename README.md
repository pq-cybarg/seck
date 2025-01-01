# seck

Sandboxed-LLM file/project analyzer with a machine-checked IO boundary.

Run a local LLM (llama.cpp / Ollama / MLX) against a file or directory inside an OS-level sandbox, with a Rust typestate that statically prevents untrusted bytes from ever reaching `argv` / `env` / paths / URLs / DNS — and a Lean 4 proof that the IO boundary holds for every well-typed host/reader program.

No cloud APIs. No telemetry. No network egress during analysis. Post-quantum crypto throughout (SHA3-256, SLH-DSA, ML-DSA, ML-KEM, Argon2id).

## Status

All 17 implementation plans complete (`v0.1.0-plan01` through `v2.0.0-plan17`). See `docs/superpowers/plans/` for the per-plan breakdown.

| Layer | Status |
|---|---|
| Linux sandbox (Landlock + seccomp + ns) | ✅ runtime-verified in qemu Ubuntu 24.04 |
| macOS sandbox (Seatbelt SBPL) | ✅ runtime-verified on macOS 26 Tahoe |
| Windows sandbox (AppContainer + Job + mitigations) | ✅ code-only; CI on `windows-2022` |
| Container sandbox (rootless podman, Approach C) | ✅ |
| Two-process capability split (Approach B) | ✅ — `seck-reader-priv` provably has no `seck-taint` dep |
| Lean 4 IO-boundary proof | ✅ zero `sorry`/`admit` in load-bearing files |
| Three-pass pipeline (analyst / auditor / judge, det@temp=0+seed) | ✅ |
| Hash-chained ML-DSA-signed audit log | ✅ |
| MCP / Web / TUI / CLI interfaces | ✅ |
| Linux desktop integration (DBus FD-handoff, `.desktop` entries) | ✅ |
| Mobile share-targets (iOS / Android over LAN WireGuard) | ✅ scaffolded; mobile JNI/Swift glue per-executor |
| Reproducible PQ-signed releases (SLH-DSA-SHAKE-128s) | ✅ |

## Quick start

```sh
cargo build --release --workspace
./target/release/seck analyze ./README.md
```

```text
seck — Sandboxed-LLM file/project analyzer

Commands:
  analyze       Analyze a file or directory inside a sandboxed LLM pipeline
  audit         Manage the per-machine audit log (init / verify / tip)
  models        Manage model files (verify SHA3-256 + signature)
  mcp           Run the MCP server over stdio
  web           Serve an HTML report locally (localhost-only, strict CSP)
  tui           Open a saved report in the terminal UI (ratatui, no mouse)
  verify-proof  Verify the Lean 4 proof of the IO-boundary theorem builds clean
  pair          Pair a mobile share-target via WireGuard-on-LAN
```

### Sandbox modes

```sh
seck analyze ./project --sandbox-mode=a   # single sandboxed reader  (default)
seck analyze ./project --sandbox-mode=b   # two-process capability split (Approach B)
# Approach C (rootless podman container) lives in seck-sandbox::container.
```

Mode B fork+execs `seck-reader` (sees bytes, base64-encodes into IPC) and `seck-reader-priv` (consumes structured IPC, runs inference). `seck-reader-priv` has no `seck-taint` Cargo dependency — `scripts/check-approach-b-invariant.sh` is the CI gate. The bytes process is incapable of leaking a `Tainted<T>` via argv/env because the type isn't in scope there.

### FD / HANDLE handoff (GUI integrations)

The path itself never appears in `seck`'s argv. The host (drag-and-drop applet, file-manager portal, Files context menu) opens the target with `O_RDONLY | O_NOFOLLOW` and passes the open FD:

```sh
exec 7</path/to/target.rs
seck analyze --fd=7                       # Unix
seck analyze --handle=12345               # Windows (HANDLE via STARTUPINFOEXW)
```

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│ host process                                                          │
│   walks path, openat2(RESOLVE_NO_SYMLINKS|NO_MAGICLINKS|NO_XDEV),    │
│   wraps every byte in Tainted<T: Zeroize>                            │
│   ─── sole sink: write_to_sandbox_pipe(Tainted, &SandboxFd<Stdin>) ─┐ │
│                                                                    │ │
│   spawns reader; applies platform sandbox in pre_exec              │ │
└────────────────────────────────────────────────────────────────────┼─┘
                                                                     │
                                ┌────────────────────────────────────▼─┐
                                │ in-sandbox reader                     │
                                │   reads FD 3, assembles nonce-        │
                                │   delimited prompt, runs inference,   │
                                │   writes JSON report to FD 5          │
                                │   ─── no other syscalls allowed ───   │
                                └───────────────────────────────────────┘
```

The Lean 4 proof in `proof/` models the host and the reader, then proves:

```lean
theorem io_boundary (h : HostProgram) (r : ReaderProgram) :
    (HostProgram.toTrace h).satisfiesIOBoundary
  ∧ (ReaderProgram.toTrace r).satisfiesIOBoundary
```

`satisfiesIOBoundary` says: every `openP` path is untainted, every `execP` path/argv/env is untainted, no `netConn` step exists, every `writeF` of tainted bytes goes to FD 3 or FD 5. Run `seck verify-proof` (requires `lake`) — must complete with zero `sorry`.

## Crypto

All primitives are post-quantum or memory-hard. The `--fips` flag locks the runtime to FIPS-203/204/205 parameter sets.

| Use | Algorithm |
|---|---|
| Hashing (file SHA, audit chain, nonce commitments) | **SHA3-256** (Keccak) — SHA-2 is forbidden, enforced by `scripts/audit-no-sha2.sh` |
| Release signatures (offline keys) | **SLH-DSA-SHAKE-128s** (FIPS 205) |
| Audit-log record signatures | **ML-DSA-65** (FIPS 204) |
| Reserved KEM slot | **ML-KEM-768** (FIPS 203) |
| Memory-hard KDF | **Argon2id** (m ≥ 512 MiB, t ≥ 4, p ≥ 4) |
| Symmetric AEAD | **AES-256-GCM-SIV** / **XChaCha20-Poly1305** |
| Mobile pairing (Plan 17) | **X25519** + 32-byte PSK, LAN/loopback-only |

## Three-layer verification

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. Rust typestate                                                │
│    Tainted<T>: no public conversion to OsString / PathBuf /     │
│    CString / &str / Command::arg / env / File::open / ...       │
│    20 trybuild compile-fail cases assert the discipline.        │
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │ enforced by
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. Runtime ptrace canary                                         │
│    Every CI run injects a unique canary into the input and     │
│    asserts via strace it never appears in argv / env / paths /  │
│    socket destinations.                                          │
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │ enforced by
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. Lean 4 proof + Rust trace-check                               │
│    proof/Seck/IOBoundary.lean (no sorry) + seck-trace-check     │
│    (fuzz-driven Rust analog of the decidable checker).          │
└─────────────────────────────────────────────────────────────────┘
```

A real exploit would have to evade all three at once. The correspondence between the Rust types and the Lean axioms is audited (not mechanically extracted — Rust has no verified compiler); see `proof/CORRESPONDENCE.md`.

## Workspace layout

```
crates/
  seck-taint              — Tainted<T> phantom-typed wrapper
  seck-fd                 — SandboxFd<Tag>, sole-sink write_to_sandbox_pipe
  seck-host-unsafe        — openat2 / O_NOFOLLOW path resolvers (quarantined unsafe)
  seck-host               — fileset assembly + sandboxed-reader orchestrator(s)
  seck-sandbox            — Landlock / Seatbelt / AppContainer / podman backends
  seck-reader             — in-sandbox process; analyze OR --mode=bytes-to-ipc (B)
  seck-reader-priv        — Approach-B inference orchestrator (NO seck-taint dep)
  seck-reader-ipc         — line-delimited JSON IPC between bytes ↔ priv
  seck-infer              — llama.cpp / Ollama / MLX backends
  seck-pipeline           — three-pass analyst/auditor/judge with PassRole seeds
  seck-canaries           — decoy prompt-injection payloads with unique markers
  seck-models             — manifest parser, SHA3-256 verify, recommend
  seck-crypto             — hash/sign/kem/kdf/sym/fips/device_key + NIST KATs
  seck-mem-hard           — LockedBytes (mlock + zeroize)
  seck-audit              — hash-chained ML-DSA-signed audit log
  seck-host-net           — quarantined TLS downloader (host-side, allow-listed)
  seck-mcp                — hand-rolled MCP JSON-RPC 2.0 server (no SDK)
  seck-web                — axum localhost-only HTML reports with strict CSP
  seck-tui                — ratatui no-mouse three-pane report viewer
  seck-cli                — `seck` binary (Clap)
  seck-report             — sanitizer + renderer (strips ANSI/OSC/BiDi/ZWJ)
  seck-bench              — public benchmark corpus runner + scorer
  seck-portal             — Linux DBus FD-handoff service
  seck-release-sign       — SLH-DSA reproducible release signer
  seck-verify-release     — SLH-DSA release verifier
  seck-trace-check        — Rust analog of Trace.checkIOBoundary (fuzz-driven)
  seck-pair               — WG endpoint + QR pairing + LAN-only enforcement
  seck-plugin             — backend trait definitions

proof/                    — Lean 4 Lake project (Basic, Effects, Origin,
                            HostModel, ReaderModel, Correspondence,
                            IOBoundary, Checker) + CORRESPONDENCE.md

platform/
  macos/                  — Seatbelt SBPL + Seck.app applet (Swift)
  linux/                  — seccomp.bpf.toml + landlock.toml + .desktop entries
  windows/                — SeckShellExt MSIX sparse package + Seck.psm1
  ios/SeckShare/          — Share Extension scaffold (Swift)
  android/seckshare/      — Share-target Activity scaffold (Kotlin)

tests/
  compile-fail/           — 20 typestate trybuild cases
  escape/                 — 6 Linux sandbox-escape regressions
  escape-macos/           — 6 macOS Seatbelt-escape regressions
  escape-windows/         — 4 AppContainer-escape regressions (code-only)
  integration/            — end-to-end smoke
  pipeline/               — three-pass orchestrator integration
  pair/                   — handshake + unpaired-refused + LAN-only

scripts/
  audit-no-sha2.sh                    — forbid SHA-2 in source
  check-approach-b-invariant.sh       — forbid seck-taint dep in seck-reader-priv
  brew/ debian/ rpm/ void/ aur/ alpine/ install.sh   — multi-distro packaging

fuzz/                     — cargo-fuzz: prompt_assembler, report_sanitizer,
                            protocol_parser, trace_invariant

.github/workflows/        — ci.yml, macos.yml, windows.yml, proof.yml,
                            trace-vs-model.yml, repro.yml, release.yml,
                            crypto-audit.yml
```

## Determinism

LLMs are not opaque — they are deterministic when you fix `temperature=0` and the seed. seck does. Same model + same input + same seed ⇒ same output bytes, byte-for-byte. Every report includes SHA3-256 of inputs, model, sandbox profile, and the per-pass seed for independent reproduction.

## Reproducible releases

Tarballs are built reproducibly (sorted entries, fixed mtime, normalized perms) and signed with SLH-DSA-SHAKE-128s offline. Verify a downloaded binary with `seck-verify-release --pubkey RELEASE_KEY.pub --binary seck --sig seck.slhdsa`. See `docs/RELEASE_KEY.md`.

## Build

```sh
cargo build --workspace                 # all 29 crates
cargo test  --workspace                 # full test suite
seck verify-proof                       # Lean 4: requires `lake` on PATH
bash scripts/check-approach-b-invariant.sh
bash scripts/audit-no-sha2.sh
```

Platform targets:

- Linux ≥ 5.13 (Landlock + PR_SET_NO_NEW_PRIVS)
- macOS ≥ 12 (Seatbelt SBPL)
- Windows 10 ≥ 19041 (AppContainer + Job)
- WSL2 (uses Linux sandbox unchanged; auto-detected)

## Security

See `SECURITY.md` and `docs/THREAT_MODEL.md`. Vulnerabilities to <resistant@tuta.com> with subject `seck security: …`.

## License

AGPL-3.0-or-later.
