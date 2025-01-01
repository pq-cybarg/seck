import Seck.Effects
import Seck.Origin

namespace Seck

/-- Model of `seck-host`. A host program is a list of `HostStep`s that
the orchestrator may legally perform. Each `HostStep` lowers to an
`Effect` via `HostStep.toEffect`.

We capture the *capability discipline* directly in the constructors:

- `spawnChild` takes `argv : List TaggedBytes` and `env : List (TaggedBytes × TaggedBytes)`
  but the Plan 01 typestate guarantees that everything reachable from
  `Command::arg`/`Command::env` is `Untainted` (constant origin). The
  axiom in `Correspondence.lean` restates that guarantee at the model
  level.
- `pipeBytes` is the *only* step that emits a `writeF` Effect. Its FD
  is fixed to `hostStdinSinkFd = 3`, and its payload may be `Tainted`.
- The host has no constructor for `netConn`. By structural induction,
  no host trace contains one. -/
inductive HostStep where
  | openInput  : Path → HostStep
  | readInput  : Fd → HostStep
  | spawnChild : Path → List TaggedBytes → List (TaggedBytes × TaggedBytes) → HostStep
  | pipeBytes  : TaggedBytes → HostStep
  | readReport : Fd → HostStep

structure HostProgram where
  steps : List HostStep

def HostStep.toEffect : HostStep → Effect
  | .openInput  p          => .openP p
  | .readInput  fd         => .readF fd
  | .spawnChild p argv env => .execP p argv env
  | .pipeBytes  b          => .writeF hostStdinSinkFd b
  | .readReport fd         => .readF fd

def HostProgram.toTrace (h : HostProgram) : Trace :=
  { steps := h.steps.map HostStep.toEffect }

end Seck
