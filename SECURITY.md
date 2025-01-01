# Security policy

## Reporting

Email <forrest.z.shooster@gmail.com> with subject `seck security: …`.

## What `seck` claims

1. **No input bytes appear in argv, env, paths, URLs, DNS, or shell strings** of the host process. Enforced by Rust typestate (20 `trybuild` compile-fail cases in `tests/compile-fail/`) and a runtime ptrace canary check (Plan 01 Task 20 — Linux).
2. **The in-sandbox process cannot escape the sandbox.** Enforced on Linux by Landlock + seccomp + namespaces; sandbox-escape attempts in `tests/escape/` must all be denied. On macOS, see Plan 02 (Seatbelt).
3. **No network egress occurs during analysis.** Empty network namespace; seccomp denies `socket()`.
4. **LLM output cannot inject terminal control sequences.** Sanitizer in `seck-report::sanitize` strips ANSI/OSC/BiDi/ZWJ before any rendering. 7 unit tests pass.

## What `seck` does not claim

- Defense against unknown vulnerabilities in `llama.cpp`, `landlock`, `seccompiler`, the Linux kernel, or other dependencies.
- Defense against cache-timing / EM side channels (see `docs/THREAT_MODEL.md`).
- Immunity to prompt injection. Mitigations are defense-in-depth; the formal guarantee covers the IO boundary, not LLM semantics.

## Reproducibility

All analyses run at temperature 0 with a fixed seed. Same model + same input ⇒ same output bytes. Reports include SHA3-256 of inputs and model for independent verification.
