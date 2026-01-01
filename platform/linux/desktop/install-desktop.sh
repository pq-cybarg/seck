#!/usr/bin/env bash
# Idempotent installer for the Linux desktop integration files.
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"

# .desktop entry
mkdir -p "$HOME/.local/share/applications"
install -m 0644 "$SRC/seck-analyze.desktop" "$HOME/.local/share/applications/"

# DBus session service
mkdir -p "$HOME/.local/share/dbus-1/services"
install -m 0644 "$SRC/net.seck.Analyze.service" "$HOME/.local/share/dbus-1/services/"

# KDE Dolphin
mkdir -p "$HOME/.local/share/kio/servicemenus"
install -m 0644 "$SRC/seck-analyze.servicemenu" "$HOME/.local/share/kio/servicemenus/"

# Nautilus
mkdir -p "$HOME/.local/share/nautilus-python/extensions"
install -m 0644 "$SRC/nautilus-seck.py" "$HOME/.local/share/nautilus-python/extensions/"

# Thunar — merge if existing uca.xml present.
mkdir -p "$HOME/.config/Thunar"
if [[ -f "$HOME/.config/Thunar/uca.xml" ]] && ! grep -q "net.seck.Analyze" "$HOME/.config/Thunar/uca.xml"; then
  # Naive merge: insert our action before </actions>.
  ACTION_BODY="$(sed -n '/<action>/,/<\/action>/p' "$SRC/seck-analyze.uca.xml")"
  awk -v body="$ACTION_BODY" '
    /<\/actions>/ { print body }
    { print }
  ' "$HOME/.config/Thunar/uca.xml" > "$HOME/.config/Thunar/uca.xml.new"
  mv "$HOME/.config/Thunar/uca.xml.new" "$HOME/.config/Thunar/uca.xml"
elif [[ ! -f "$HOME/.config/Thunar/uca.xml" ]]; then
  install -m 0644 "$SRC/seck-analyze.uca.xml" "$HOME/.config/Thunar/uca.xml"
fi

echo "Installed."
echo "Restart Files / Dolphin / Thunar to pick up the new menu entry."
