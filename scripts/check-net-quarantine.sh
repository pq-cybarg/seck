#!/usr/bin/env bash
# Fail CI if any analysis-path crate gains a dependency on seck-host-net.
# The intent is that ONLY seck-cli (the user-facing entry point) and
# seck-models (the cache-layout helper) can touch the network code; the
# crates that actually run the sandboxed analysis MUST NOT.
set -euo pipefail
cd "$(dirname "$0")/.."

FORBIDDEN_CRATES=(
  "seck-host"
  "seck-host-unsafe"
  "seck-reader"
  "seck-sandbox"
  "seck-taint"
  "seck-fd"
  "seck-plugin"
  "seck-proto"
  "seck-infer"
  "seck-report"
  "seck-audit"
  "seck-mem-hard"
  "seck-crypto"
)

fail=0
for c in "${FORBIDDEN_CRATES[@]}"; do
  if grep -qE '^seck-host-net' "crates/$c/Cargo.toml" 2>/dev/null; then
    echo "FAIL: crate '$c' depends on seck-host-net (net code must be quarantined)" >&2
    fail=1
  fi
done
if [[ "$fail" -ne 0 ]]; then
  exit 1
fi
echo "OK: net code is quarantined to seck-host-net (used only by seck-cli + seck-models)."
