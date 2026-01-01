#!/usr/bin/env bash
# CI gate: seck-reader-priv (Approach B inference orchestrator) MUST NOT
# depend on seck-taint. The whole point of the two-process split is
# that the inference process never sees a `Tainted<Vec<u8>>`.
#
# A `Tainted<T>` can only be constructed in a crate that depends on
# `seck-taint`. By forbidding the dep in seck-reader-priv's Cargo.toml,
# the type is unrepresentable in that crate — the compiler cannot
# accept any code that mentions it.
set -euo pipefail
cd "$(dirname "$0")/.."

CARGO="crates/seck-reader-priv/Cargo.toml"
if [[ ! -f "$CARGO" ]]; then
  echo "FAIL: $CARGO missing" >&2
  exit 1
fi

if grep -qE '^seck-taint\b|^seck-taint =' "$CARGO"; then
  echo "FAIL: $CARGO lists seck-taint as a dependency. Approach B forbids this." >&2
  grep -n -E '^seck-taint' "$CARGO" >&2
  exit 1
fi

# Also catch indirect re-export: priv must not import any crate that
# itself re-exports seck-taint::Tainted publicly.
if grep -qE 'use seck_taint' "$CARGO" 2>/dev/null; then
  echo "FAIL: $CARGO mentions seck_taint" >&2
  exit 1
fi

if grep -qE '\buse\s+seck_taint::' crates/seck-reader-priv/src/*.rs 2>/dev/null; then
  echo "FAIL: seck-reader-priv source imports seck_taint" >&2
  grep -nE '\buse\s+seck_taint::' crates/seck-reader-priv/src/*.rs >&2
  exit 1
fi

echo "OK: seck-reader-priv has no dependency on seck-taint (Approach B invariant holds)."
