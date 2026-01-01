#!/usr/bin/env bash
# Build Seck.app — a thin Swift wrapper that drag-and-drop spawns the seck
# CLI with the dropped path opened as a pre-opened FD (never as argv).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
APP_DIR="$ROOT/target/Seck.app"

# Pre-flight: seck + seck-reader must be built.
for bin in seck seck-reader; do
  if [[ ! -x "$ROOT/target/release/$bin" ]]; then
    echo "build_applet.sh: $ROOT/target/release/$bin not found; run 'cargo build --release --workspace' first" >&2
    exit 1
  fi
done

rm -rf "$APP_DIR"
mkdir -p "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources"

cd "$ROOT/platform/macos/applet"
swift build -c release

cp .build/release/SeckApplet  "$APP_DIR/Contents/MacOS/SeckApplet"
cp Info.plist                 "$APP_DIR/Contents/Info.plist"

# Embed the seck CLI binaries so the applet finds them next to itself.
cp "$ROOT/target/release/seck"        "$APP_DIR/Contents/Resources/seck"
cp "$ROOT/target/release/seck-reader" "$APP_DIR/Contents/Resources/seck-reader"

# Adhoc-sign for local development. A real distribution build (Plan 15)
# will replace this with a Developer ID + notarization.
codesign --force --sign - --timestamp=none --deep "$APP_DIR"

echo "Built $APP_DIR"
