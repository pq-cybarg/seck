#!/usr/bin/env bash
set -euo pipefail
rm -f "$HOME/.local/share/applications/seck-analyze.desktop"
rm -f "$HOME/.local/share/dbus-1/services/net.seck.Analyze.service"
rm -f "$HOME/.local/share/kio/servicemenus/seck-analyze.servicemenu"
rm -f "$HOME/.local/share/nautilus-python/extensions/nautilus-seck.py"
# Thunar: leave $HOME/.config/Thunar/uca.xml alone; user may have merged
# their own actions in.
echo "Removed Linux desktop integration. Thunar uca.xml left alone."
