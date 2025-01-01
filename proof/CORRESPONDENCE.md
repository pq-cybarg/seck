# Rust ↔ Lean Correspondence

The IO-boundary proof in `proof/Seck/IOBoundary.lean` discharges every
case via either (a) the constructors of `HostStep` and `ReaderStep`
(which by definition cannot produce certain `Effect`s — e.g., the host
has no constructor mapping to `netConn`, the reader has no constructor
mapping to `openP`), or (b) two correspondence **axioms**:

```lean
axiom no_tainted_to_untainted_conversion : ...
axiom reader_exec_path_untainted          : ...
```

The intuitive content of those axioms: in any host program, the bytes
that flow into `openInput` paths, `spawnChild` paths/argv/env entries,
or any `netConn` (none — the constructor doesn't exist) are **all
untainted**; and the only path the reader ever execs is untainted (it
points at a binary the host opened before sandbox lockdown).

We do not extract these axioms mechanically from the Rust source. The
correspondence is **audited**, and the audit is enforced by three
independent runtime mechanisms — any single bypass would still be
caught by the other two:

1. **Rust typestate (Plan 01).** `Tainted<T>` has no public conversion
   to `OsString`, `PathBuf`, `CString`, `&str`, or anything
   `Command::arg` / `Command::env` / `std::fs::File::open` accepts.
   Twenty `trybuild` compile-fail cases exercise the discipline.

2. **Runtime ptrace canary check (Plan 01 Task 20).** Every CI run
   injects a unique canary into the input file and asserts via
   `strace` that the canary never appears in argv, env, paths, or
   socket destinations.

3. **`seck-trace-check` (Plan 05).** A Rust harness parses real strace
   output into the same `Effect` grammar as the Lean model and runs
   the decidable checker against every CI invocation. Fuzz-driven
   (cargo-fuzz `trace_invariant`) so even adversarial trace strings
   cannot crash the parser.

If any of those three flags a violation, the implementation has broken
the axiom even though it remains true in the Lean model. The system is
designed so that a real exploit would have to evade all three at once.

A full mechanical extraction (Rust → Lean) is impossible at production
quality today — there is no verified Rust compiler. This is the same
trust posture as seL4 (verified C, but the C compiler is trusted) and
CompCert (verified compiler, but its specification is trusted). We
document the limit honestly here and in `docs/THREAT_MODEL.md`.

## Plan-04 / Approach B note

The proof models Approach **A** (single sandboxed reader): host →
reader → report. Approach B splits the reader into two processes
(`seck-reader` and `seck-reader-priv`) joined by a unidirectional IPC
pipe. The IO boundary holds in B by an *additional* structural
argument: `seck-reader-priv` is a Lean-modelable subprogram whose
`HostStep`-analog is empty (it cannot open, exec, or net-connect),
and `seck-reader-bytes` only writes structured `Message` JSON to FD 7
— never raw bytes to argv/env/path. The workspace-level CI gate
(`scripts/check-approach-b-invariant.sh`) proves at the *type* level
that `seck-reader-priv` has no `seck-taint` dependency, which is the
Rust-side analog of "the constructor doesn't exist". Extending the
Lean proof to model B explicitly is tagged as a follow-up patch.
