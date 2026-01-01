#!/usr/bin/env bash
# trace_audit.sh — IO-boundary canary check via strace.
#
# 1. Write a small file with a unique random canary string in it.
# 2. Run `seck analyze` on that file under strace, recording exec/open/net/
#    write syscalls.
# 3. Assert the canary appears ONLY in write(3, ...) — the sandbox stdin
#    pipe. ANY appearance in:
#       - openat / openat2 path
#       - execve / execveat path or argv
#       - connect / sendto / sendmsg
#       - write(fd, ...) with fd ∉ {3, 5, 1, 2}
#    is a sandbox-boundary regression.
#
# Linux only. No Python.
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "trace_audit.sh: Linux-only (uses strace)" >&2
  exit 0
fi

SECK_BIN="${SECK_BIN:-./target/release/seck}"
if [[ ! -x "$SECK_BIN" ]]; then
  echo "trace_audit.sh: $SECK_BIN not found / not executable" >&2
  exit 2
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

CANARY="SECK-AUDIT-$(head -c 16 /dev/urandom | xxd -p)"
TARGET="$TMP/payload.txt"
printf 'data line 1\n%s\nlast line\n' "$CANARY" > "$TARGET"

TRACE="$TMP/trace.log"
# -f follow children; -s 16384 capture long string args; -e trace=<list>.
strace -f -e trace=openat,openat2,execve,execveat,socket,connect,sendto,sendmsg,write,read \
       -s 16384 -o "$TRACE" \
       "$SECK_BIN" analyze "$TARGET" >/dev/null 2>&1 || true

if [[ ! -s "$TRACE" ]]; then
  echo "trace_audit.sh: strace produced no output" >&2
  exit 2
fi

violations=0

# Helper: print + count.
fail() {
  echo "TRACE-AUDIT FAIL: $1"
  echo "  line: $2"
  violations=$((violations + 1))
}

# 1. Canary in any openat/openat2 path argument.
while IFS= read -r line; do
  fail "canary appears in openat path" "$line"
done < <(grep -aE 'openat2?\([^)]*"[^"]*'"$CANARY"'[^"]*"' "$TRACE" || true)

# 2. Canary in execve/execveat path or argv.
while IFS= read -r line; do
  fail "canary appears in execve* args" "$line"
done < <(grep -aE 'execve(at)?\([^)]*'"$CANARY" "$TRACE" || true)

# 3. Canary in any network syscall.
while IFS= read -r line; do
  fail "canary appears in network syscall" "$line"
done < <(grep -aE '(socket|connect|sendto|sendmsg)\([^)]*'"$CANARY" "$TRACE" || true)

# 4. Canary in write() to any FD other than 3 (sandbox stdin), 5 (report),
#    1/2 (stdout/stderr). Pattern: write(FD, "..."), keep only FD field.
while IFS= read -r line; do
  fd=$(echo "$line" | sed -nE 's/.*write\(([0-9]+),.*/\1/p')
  case "$fd" in
    3|5|1|2) ;;  # allowed sinks
    *)       fail "canary written to fd=$fd (only fd 3/5/1/2 allowed)" "$line" ;;
  esac
done < <(grep -aE 'write\([0-9]+,[^)]*'"$CANARY" "$TRACE" || true)

if [[ "$violations" -gt 0 ]]; then
  echo
  echo "trace_audit.sh: $violations violation(s). canary='$CANARY'"
  echo "first 200 lines of trace:"
  head -200 "$TRACE"
  exit 1
fi

echo "trace_audit.sh: OK — canary leaked through ZERO forbidden syscalls (canary=${CANARY:0:24}...)"
exit 0
