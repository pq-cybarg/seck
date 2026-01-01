import Seck.IOBoundary

namespace Seck

/-- A `Bool`-valued decision procedure for `satisfiesIOBoundary`, exposed
to the Rust runtime harness (`crates/seck-trace-check`). The Rust side
parses an `strace` capture into the same `Effect` grammar and runs the
analogous check there. -/
def Trace.checkIOBoundary (t : Trace) : Bool :=
  t.steps.all (fun s =>
    match s with
    | .openP p     => ! p.contents.origin.isTainted
    | .execP p a e =>
        (! p.contents.origin.isTainted)
        && a.all (fun b => ! b.origin.isTainted)
        && e.all (fun kv => (! kv.fst.origin.isTainted) && (! kv.snd.origin.isTainted))
    | .readF _     => true
    | .writeF fd b =>
        if b.origin.isTainted then
          decide (fd ∈ allowedTaintedWriteFds)
        else true
    | .netConn _ _ => false)

end Seck
