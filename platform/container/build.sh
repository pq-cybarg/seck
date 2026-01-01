#!/usr/bin/env bash
# Reproducible OCI build via buildah. Output: localhost/seck-reader:0.1.0
# tagged image + image.manifest.toml with the resulting digest.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# Build the host-side seck-reader with deterministic flags.
RUSTFLAGS="-C link-arg=-Wl,-z,relro,-z,now -C codegen-units=1 -C opt-level=3 -C debuginfo=0 -C strip=symbols -C relocation-model=pie" \
SOURCE_DATE_EPOCH=1700000000 \
cargo build --manifest-path "$ROOT/Cargo.toml" --release --bin seck-reader

LLAMA_DIR="${LLAMA_CLI_DIR:-$ROOT/.cache/llama.cpp}"
if [[ ! -x "$LLAMA_DIR/build/bin/llama-cli" ]]; then
  echo "build.sh: $LLAMA_DIR/build/bin/llama-cli missing." >&2
  echo "  Build llama.cpp first or set LLAMA_CLI_DIR." >&2
  exit 1
fi

cp "$ROOT/target/release/seck-reader"      "$STAGE/"
cp "$LLAMA_DIR/build/bin/llama-cli"        "$STAGE/"
cp "$ROOT/platform/linux/seccomp.bpf.toml" "$STAGE/"
cp "$ROOT/platform/linux/landlock.toml"    "$STAGE/"
cp "$ROOT/platform/container/Dockerfile"   "$STAGE/Dockerfile"

cd "$STAGE"
buildah build --timestamp 1700000000 \
  --tag localhost/seck-reader:0.1.0 \
  --file Dockerfile \
  .

DIGEST="$(podman image inspect localhost/seck-reader:0.1.0 --format '{{.Digest}}')"
echo "digest = \"$DIGEST\"" > "$ROOT/platform/container/image.manifest.toml"
echo "Built localhost/seck-reader:0.1.0  digest=$DIGEST"
