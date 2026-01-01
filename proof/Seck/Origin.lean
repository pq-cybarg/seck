import Seck.Basic
namespace Seck

inductive Origin where
  | fromFile : Origin
  | constant : Origin
  | derived  : Origin → Origin                 -- e.g., hash of file bytes

/-- A byte string together with its provenance tag. Mirrors Plan 01's
`Tainted<T>` Rust type: the tag travels with the value and the
IO-boundary theorem inspects it. -/
structure TaggedBytes where
  bytes  : Bytes
  origin : Origin

def Origin.isTainted : Origin → Bool
  | .fromFile     => true
  | .constant     => false
  | .derived o    => o.isTainted

/-- Lift raw bytes into the tagged form, with a constant origin
(i.e., declared by the program, not derived from a user file). -/
def Bytes.untainted (b : Bytes) : TaggedBytes :=
  { bytes := b, origin := .constant }

/-- A path is just a `TaggedBytes` payload. The model treats argv,
env keys/values, paths, and network host bytes uniformly. -/
structure Path where
  contents : TaggedBytes

end Seck
