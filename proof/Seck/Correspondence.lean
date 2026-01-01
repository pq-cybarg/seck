import Seck.Effects
import Seck.Origin
import Seck.HostModel
import Seck.ReaderModel

namespace Seck

/-- The Rust↔Lean correspondence, stated at the model level.

It says: in any host program, the bytes appearing in (a) `openInput`
paths, (b) `spawnChild` paths, (c) `spawnChild` argv entries, and
(d) `spawnChild` env keys and values, are *all* untainted.

In Rust, this holds by construction: `Tainted<T>` has no public
conversion to `OsString`, `PathBuf`, `CString`, `&str`, or anything
`Command::arg`/`Command::env`/`std::fs::File::open` accepts. Plan 01
ships 20 `trybuild` compile-fail cases that exercise the discipline,
and Plan 01 Task 20 runs a ptrace canary check at runtime. Plan 05
Task 11 adds a third, independent enforcement: `seck-trace-check`
parses real strace output and asserts the predicate against the
recorded `Effect` stream.

See `proof/CORRESPONDENCE.md` for the full audit. -/
axiom no_tainted_to_untainted_conversion :
  ∀ (h : HostProgram), ∀ s ∈ h.steps,
      (∀ p,            s = .openInput p →
          p.contents.origin.isTainted = false)
    ∧ (∀ fp argv env,  s = .spawnChild fp argv env →
            (fp.contents.origin.isTainted = false)
          ∧ (∀ b ∈ argv,        b.origin.isTainted = false)
          ∧ (∀ kv ∈ env,
                kv.fst.origin.isTainted = false
              ∧ kv.snd.origin.isTainted = false))

/-- Reader-side correspondence: when the reader execs the inference
binary, the path is `Untainted`. (The reader has no other way to
exec, so this is the only path-bearing step to constrain.) -/
axiom reader_exec_path_untainted :
  ∀ (r : ReaderProgram), ∀ s ∈ r.steps,
      ∀ p, s = .execInfer p → p.contents.origin.isTainted = false

end Seck
