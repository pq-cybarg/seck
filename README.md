# seck

Sandboxed-LLM file/project analyzer.

See:
- `docs/superpowers/specs/2026-05-19-seck-sandboxed-llm-analyzer-design.md` — full design
- `docs/superpowers/plans/` — implementation plans 01–17 (all written; 01 and 02 partially executed)

## Quick start

```sh
cargo build --release --workspace
./target/release/seck analyze ./README.md
```

Works natively on Linux ≥ 5.13 (Landlock + PR_SET_NO_NEW_PRIVS) and macOS ≥ 12 (Seatbelt SBPL). The Linux sandbox has been runtime-verified inside a qemu Ubuntu 24.04 VM (`tests/escape` — 6/6 escapes denied). The macOS sandbox has been runtime-verified on macOS 26 Tahoe (`tests/escape-macos` — 6/6 escapes denied).

### `--fd=N` for FD-inherit invocation

For GUI integration (drag-and-drop applet, file-manager portal), open the target with `O_RDONLY | O_NOFOLLOW` on the host and pass the FD via `--fd=N`. The path itself never appears in `seck`'s argv. Example:

```sh
exec 7</path/to/target.rs
seck analyze --fd=7
```

## What's implemented

- **Plan 01** (tag `v0.1.0-plan01`): core verified IO boundary on Linux. Tasks 1–18, 20–24 done; Task 19 (cargo-fuzz) deferred (nightly toolchain).
- **Plan 02** (this branch, partial): macOS Seatbelt sandbox + `--fd=N` flag. Tasks 1–5, 7 done; Tasks 6 (Seck.app drag-and-drop applet), 8 (Finder Quick Action), 9 (CI macOS yml), 10 (this README) — applet + Quick Action + CI deferred to a follow-up.

## Tests passing

- 20 typestate compile-fail cases (`tests/compile-fail`)
- 7 sanitizer unit tests (ANSI / OSC 8 / BiDi / ZWJ / control chars stripped)
- 2 prompt-assembler unit tests
- 6 Linux sandbox-escape regressions (Landlock blocks /etc/passwd, /etc/shadow, /etc, ~/.ssh, /proc/self/environ, /tmp writes)
- 4 proptest path-resolver cases (adversarial filenames, walk limits enforced)
- 3 integration smoke tests on Linux (text file, adversarial filename, symlink refusal)
- 1 strace canary trace-audit on Linux (zero leakage to forbidden syscalls)
- 6 macOS Seatbelt-escape regressions (file-read, ~/, tcp-connect, /tmp-write, exec /bin/sh)

## Security

See `SECURITY.md` and `docs/THREAT_MODEL.md`.
