#!/usr/bin/env bash
# Install the "Analyze with seck" Quick Action into the user's Services
# directory. Idempotent: re-running replaces any previous installation.
set -euo pipefail
SRC="$(cd "$(dirname "$0")/AnalyzeWithSeck.workflow" && pwd)"
DST="$HOME/Library/Services/AnalyzeWithSeck.workflow"
rm -rf "$DST"
cp -R "$SRC" "$DST"
echo "Installed Quick Action at $DST"
echo "Right-click any file in Finder → Quick Actions → Analyze with seck."
echo "If it doesn't appear immediately, restart Finder: killall Finder"
