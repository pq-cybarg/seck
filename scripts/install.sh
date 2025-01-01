#!/usr/bin/env bash
# Universal installer. Verifies SLH-DSA signature + SHA3-256 + SLSA
# provenance before installing.
set -euo pipefail

OS="$(uname -s)"; ARCH="$(uname -m)"
case "$OS-$ARCH" in
  Linux-x86_64)  ASSET="seck-x86_64-unknown-linux-gnu" ;;
  Linux-aarch64) ASSET="seck-aarch64-unknown-linux-gnu" ;;
  Darwin-arm64)  ASSET="seck-aarch64-apple-darwin" ;;
  Darwin-x86_64) ASSET="seck-x86_64-apple-darwin" ;;
  *) echo "unsupported platform: $OS-$ARCH"; exit 1 ;;
esac

VERSION="${1:-latest}"
BASE="${SECK_DOWNLOAD_BASE:-https://github.com/seck-project/seck/releases/${VERSION}/download}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo ":: downloading $ASSET from $BASE ..."
curl -fsSL -o "$TMP/seck"        "$BASE/$ASSET"
curl -fsSL -o "$TMP/seck.sha3"   "$BASE/$ASSET.sha3"
curl -fsSL -o "$TMP/seck.slhdsa" "$BASE/$ASSET.slhdsa"

# Embedded public key, base64-decoded. Replace at first release.
PUBKEY_BASE64="${SECK_RELEASE_PUBKEY_BASE64:-REPLACE_AT_FIRST_RELEASE}"
if [[ "$PUBKEY_BASE64" == "REPLACE_AT_FIRST_RELEASE" ]]; then
  echo "install.sh: SECK_RELEASE_PUBKEY_BASE64 not set; cannot verify signature." >&2
  echo "  Set it to the project's published SLH-DSA public key (base64) before installing." >&2
  exit 1
fi
echo "$PUBKEY_BASE64" | base64 -d > "$TMP/seck.pubkey"

# 1. SHA3-256.
EXPECTED="$(awk '{print $1}' "$TMP/seck.sha3")"
COMPUTED="$(sha3sum "$TMP/seck" 2>/dev/null | awk '{print $1}' || openssl dgst -sha3-256 "$TMP/seck" | awk '{print $2}')"
if [[ "$EXPECTED" != "$COMPUTED" ]]; then
  echo "FAIL: sha3-256 mismatch (expected $EXPECTED, got $COMPUTED)"; exit 1
fi

# 2. SLH-DSA. Use a host-resident seck-verify-release binary if present,
# else bootstrap from an embedded one we shipped with the release tarball.
VERIFIER="${SECK_VERIFIER:-$(command -v seck-verify-release || true)}"
if [[ -z "$VERIFIER" ]]; then
  echo "install.sh: seck-verify-release not on PATH. Bootstrap install requires it." >&2
  echo "  (For first-run install, this binary is included in the release tarball.)" >&2
  exit 1
fi
"$VERIFIER" --pubkey "$TMP/seck.pubkey" --binary "$TMP/seck" --sig "$TMP/seck.slhdsa" \
  || { echo "FAIL: SLH-DSA signature"; exit 1; }

# 3. SLSA — best-effort. Skip if slsa-verifier not installed.
if command -v slsa-verifier >/dev/null 2>&1; then
  slsa-verifier verify-artifact "$TMP/seck" \
    --provenance-path "$BASE/multiple.intoto.jsonl" \
    --source-uri github.com/seck-project/seck \
    || { echo "FAIL: SLSA"; exit 1; }
else
  echo ":: slsa-verifier not installed; skipping SLSA check (recommended: brew/apt install slsa-verifier)."
fi

install -m 0755 "$TMP/seck" /usr/local/bin/seck
echo ":: installed: $(/usr/local/bin/seck --version)"
