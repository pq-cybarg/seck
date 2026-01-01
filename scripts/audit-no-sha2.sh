#!/usr/bin/env bash
# Fail if any SHA-2 / SHA-256 reference (other than docs) appears in
# source. SHA-2 must never be used by seck — all hashing is SHA3-256.
set -euo pipefail

cd "$(dirname "$0")/.."

# Find candidate matches in source files only.
matches=$(grep -RInE '\b(sha[-_ ]?256|Sha256|SHA-?2|sha2)\b' \
  --include='*.rs' \
  --include='*.toml' \
  --include='*.lean' \
  --include='*.swift' \
  --exclude-dir=target \
  --exclude-dir=target-linux \
  --exclude-dir=target-escape \
  --exclude-dir='.git' \
  --exclude-dir=node_modules \
  . || true)

# Filter out SHA-3 mentions (regex above matches `sha256` inside `sha3-256`
# and `sha3_256`). Also filter out crate-name dependencies for `sha3` which
# happens to have "256" in version strings.
filtered=$(echo "$matches" | grep -vE '(sha3[-_]?256|sha3_256|SHA3|sha-3|SHA-3|seck-fuzz|libfuzzer)' || true)

if [[ -n "$filtered" ]]; then
  echo "FAIL: SHA-2 / SHA-256 references found in source:" >&2
  echo "$filtered" >&2
  exit 1
fi
echo "OK: no SHA-2 references in source."
