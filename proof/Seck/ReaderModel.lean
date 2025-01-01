import Seck.Effects
import Seck.Origin

namespace Seck

/-- Model of `seck-reader`. Inside the sandbox the reader can:

- read FD 3 (input frames from the host),
- exec the pre-opened inference binary (the path is `Untainted`
  because the host opened it before the sandbox was applied),
- write the JSON report to FD 5.

The model has no constructor for opening additional paths, for
spawning arbitrary children, or for opening sockets. By structural
induction, no reader trace contains those Effects. -/
inductive ReaderStep where
  | readInput    : ReaderStep
  | execInfer    : Path → ReaderStep
  | writeReport  : TaggedBytes → ReaderStep

structure ReaderProgram where
  steps : List ReaderStep

def ReaderStep.toEffect : ReaderStep → Effect
  | .readInput        => .readF hostStdinSinkFd
  | .execInfer p      => .execP p [] []
  | .writeReport b    => .writeF sandboxReportFd b

def ReaderProgram.toTrace (r : ReaderProgram) : Trace :=
  { steps := r.steps.map ReaderStep.toEffect }

end Seck
