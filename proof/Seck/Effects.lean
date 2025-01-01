import Seck.Basic
import Seck.Origin
namespace Seck

/-- The grammar of observable IO effects. The Rust runtime side
emits one of these per syscall; the Lean side defines `satisfiesIOBoundary`
on traces over this grammar. -/
inductive Effect where
  | openP    : Path → Effect
  | execP    : (path : Path)
               → (args : List TaggedBytes)
               → (env  : List (TaggedBytes × TaggedBytes))
               → Effect
  | readF    : Fd → Effect
  | writeF   : Fd → TaggedBytes → Effect
  | netConn  : TaggedBytes → Nat → Effect      -- host bytes, port

structure Trace where
  steps : List Effect

end Seck
