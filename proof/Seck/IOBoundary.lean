import Seck.Correspondence

namespace Seck

/-- The set of FDs to which `Tainted` writes are permitted. -/
def allowedTaintedWriteFds : List Fd := [hostStdinSinkFd, sandboxReportFd]

/-- A trace satisfies the IO boundary if:
  1. every `openP` path is untainted,
  2. every `execP` path/argv/env entry is untainted,
  3. there are no `netConn` steps,
  4. every `writeF` of a tainted payload goes to an allowed FD. -/
def Trace.satisfiesIOBoundary (t : Trace) : Prop :=
    (∀ s ∈ t.steps, ∀ p, s = .openP p →
        p.contents.origin.isTainted = false)
  ∧ (∀ s ∈ t.steps, ∀ fp argv env, s = .execP fp argv env →
            (fp.contents.origin.isTainted = false)
          ∧ (∀ b ∈ argv, b.origin.isTainted = false)
          ∧ (∀ kv ∈ env,
                kv.fst.origin.isTainted = false
              ∧ kv.snd.origin.isTainted = false))
  ∧ (∀ s ∈ t.steps, ∀ host port, s ≠ .netConn host port)
  ∧ (∀ s ∈ t.steps, ∀ fd b, s = .writeF fd b →
        b.origin.isTainted = true → fd ∈ allowedTaintedWriteFds)

------------------------------------------------------------------------
-- Host-side IO boundary
------------------------------------------------------------------------

theorem host_satisfies_io_boundary (h : HostProgram) :
    (HostProgram.toTrace h).satisfiesIOBoundary := by
  refine ⟨?openP, ?execP, ?noNet, ?writes⟩
  case openP =>
    intro s hs p heq
    -- s comes from some HostStep
    simp [HostProgram.toTrace] at hs
    obtain ⟨step, hstep, hmap⟩ := hs
    -- Only .openInput maps to .openP
    cases step with
    | openInput pin =>
        -- HostStep.toEffect (.openInput pin) = .openP pin
        simp [HostStep.toEffect] at hmap
        -- so s = .openP pin and heq says .openP pin = .openP p
        subst hmap
        cases heq
        -- Apply the correspondence axiom on the original step.
        have h1 := no_tainted_to_untainted_conversion h _ hstep
        exact h1.1 p rfl
    | readInput  _ => simp [HostStep.toEffect] at hmap; subst hmap; cases heq
    | spawnChild _ _ _ => simp [HostStep.toEffect] at hmap; subst hmap; cases heq
    | pipeBytes  _ => simp [HostStep.toEffect] at hmap; subst hmap; cases heq
    | readReport _ => simp [HostStep.toEffect] at hmap; subst hmap; cases heq
  case execP =>
    intro s hs fp argv env heq
    simp [HostProgram.toTrace] at hs
    obtain ⟨step, hstep, hmap⟩ := hs
    cases step with
    | openInput _ => simp [HostStep.toEffect] at hmap; subst hmap; cases heq
    | readInput _ => simp [HostStep.toEffect] at hmap; subst hmap; cases heq
    | spawnChild p0 argv0 env0 =>
        simp [HostStep.toEffect] at hmap
        subst hmap
        -- heq : .execP p0 argv0 env0 = .execP fp argv env
        -- After `cases heq`, the constructor-binders (p0/argv0/env0)
        -- are eliminated in favor of the goal-binders (fp/argv/env).
        cases heq
        have h1 := no_tainted_to_untainted_conversion h _ hstep
        exact h1.2 fp argv env rfl
    | pipeBytes _ => simp [HostStep.toEffect] at hmap; subst hmap; cases heq
    | readReport _ => simp [HostStep.toEffect] at hmap; subst hmap; cases heq
  case noNet =>
    intro s hs host port heq
    simp [HostProgram.toTrace] at hs
    obtain ⟨step, _, hmap⟩ := hs
    cases step <;>
      (simp [HostStep.toEffect] at hmap
       subst hmap
       cases heq)
  case writes =>
    intro s hs fd b heq _
    simp [HostProgram.toTrace] at hs
    obtain ⟨step, _, hmap⟩ := hs
    cases step with
    | openInput _ => simp [HostStep.toEffect] at hmap; subst hmap; cases heq
    | readInput _ => simp [HostStep.toEffect] at hmap; subst hmap; cases heq
    | spawnChild _ _ _ => simp [HostStep.toEffect] at hmap; subst hmap; cases heq
    | pipeBytes b0 =>
        simp [HostStep.toEffect] at hmap
        subst hmap
        -- heq : .writeF hostStdinSinkFd b0 = .writeF fd b
        injection heq with hfd _
        subst hfd
        -- show hostStdinSinkFd ∈ allowedTaintedWriteFds
        simp [allowedTaintedWriteFds]
    | readReport _ => simp [HostStep.toEffect] at hmap; subst hmap; cases heq

------------------------------------------------------------------------
-- Reader-side IO boundary
------------------------------------------------------------------------

theorem reader_satisfies_io_boundary (r : ReaderProgram) :
    (ReaderProgram.toTrace r).satisfiesIOBoundary := by
  refine ⟨?openP, ?execP, ?noNet, ?writes⟩
  case openP =>
    intro s hs p heq
    simp [ReaderProgram.toTrace] at hs
    obtain ⟨step, _, hmap⟩ := hs
    cases step <;>
      (simp [ReaderStep.toEffect] at hmap
       subst hmap
       cases heq)
  case execP =>
    intro s hs fp argv env heq
    simp [ReaderProgram.toTrace] at hs
    obtain ⟨step, hstep, hmap⟩ := hs
    cases step with
    | readInput => simp [ReaderStep.toEffect] at hmap; subst hmap; cases heq
    | execInfer p0 =>
        simp [ReaderStep.toEffect] at hmap
        subst hmap
        cases heq
        refine ⟨?p, ?a, ?e⟩
        · exact reader_exec_path_untainted r _ hstep fp rfl
        · intro b hb; cases hb
        · intro kv hkv; cases hkv
    | writeReport _ => simp [ReaderStep.toEffect] at hmap; subst hmap; cases heq
  case noNet =>
    intro s hs host port heq
    simp [ReaderProgram.toTrace] at hs
    obtain ⟨step, _, hmap⟩ := hs
    cases step <;>
      (simp [ReaderStep.toEffect] at hmap
       subst hmap
       cases heq)
  case writes =>
    intro s hs fd b heq _
    simp [ReaderProgram.toTrace] at hs
    obtain ⟨step, _, hmap⟩ := hs
    cases step with
    | readInput => simp [ReaderStep.toEffect] at hmap; subst hmap; cases heq
    | execInfer _ => simp [ReaderStep.toEffect] at hmap; subst hmap; cases heq
    | writeReport b0 =>
        simp [ReaderStep.toEffect] at hmap
        subst hmap
        injection heq with hfd _
        subst hfd
        simp [allowedTaintedWriteFds]

/-- **Main theorem.** Any host program and any reader program, both
built from our model's constructors, satisfy the IO boundary. The
proof is by structural induction over the program's `Step` list,
discharging each case either via the correspondence axioms (for
content-bearing effects) or by structural impossibility (the model's
constructors simply do not produce certain effects, e.g., `netConn`). -/
theorem io_boundary
    (h : HostProgram) (r : ReaderProgram) :
    (HostProgram.toTrace h).satisfiesIOBoundary
    ∧ (ReaderProgram.toTrace r).satisfiesIOBoundary :=
  ⟨host_satisfies_io_boundary h, reader_satisfies_io_boundary r⟩

end Seck
