#!/usr/bin/env bash
# NIDS Installer — double-click or run: ./install_desktop.sh
# Installs dependencies, sets permissions, adds NIDS to the app menu.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=============================="
echo "  NIDS Installer"
echo "=============================="
echo ""

# 1. Check Python 3
if ! command -v python3 &>/dev/null; then
  echo "[ERROR] Python 3 is not installed."
  echo "  Run:  sudo apt install python3 python3-pip"
  read -rp "Press Enter to exit..."
  exit 1
fi
echo "[OK] Python 3 found"

# 2. Install Python dependencies
if [[ -f "$ROOT/requirements.txt" ]]; then
  echo "[...] Installing Python packages..."
  pip3 install -r "$ROOT/requirements.txt" 2>/dev/null \
    || pip3 install --user -r "$ROOT/requirements.txt" 2>/dev/null \
    || sudo pip3 install -r "$ROOT/requirements.txt" \
    || { echo "[ERROR] Could not install dependencies. Try: sudo pip3 install -r requirements.txt"; }
  echo "[OK] Dependencies installed"
else
  echo "[WARN] requirements.txt not found — skipping dependency install"
fi

# 3. Set permissions
chmod +x "$ROOT/nids.sh" 2>/dev/null || true
chmod +x "$ROOT/install_desktop.sh" 2>/dev/null || true
if [[ -f "$ROOT/icons/nids.png" ]]; then
  chmod a+r "$ROOT/icons/nids.png" 2>/dev/null || true
fi
echo "[OK] Permissions set"

# 4. Create app menu entry
VERSION="$(grep -E '^APP_VERSION\s*=' "$ROOT/gui.py" 2>/dev/null | sed -n 's/.*"\([^"]*\)".*/\1/p')"
[[ -z "$VERSION" ]] && VERSION="2.1"

DESKTOP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
mkdir -p "$DESKTOP_DIR"

cat > "$DESKTOP_DIR/nids.desktop" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=NIDS v${VERSION}
Comment=Network Intrusion Detection System
Exec=${ROOT}/nids.sh
Icon=${ROOT}/icons/nids.png
Terminal=false
Categories=Network;Security;System;
Keywords=firewall;intrusion;detection;network;security;
StartupNotify=false
EOF

chmod +x "$DESKTOP_DIR/nids.desktop"

if command -v update-desktop-database &>/dev/null; then
  update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
fi
echo "[OK] Menu entry created"

# 5. Done
echo ""
echo "=============================="
echo "  Installation complete!"
echo "=============================="
echo ""
echo "  To run:  Open app menu → search 'NIDS'"
echo "           Or:  cd $ROOT && ./nids.sh"
echo ""
echo "  Note: NIDS requires root for packet capture."
echo "  The launcher will prompt for your password."
echo ""
read -rp "Press Enter to close..."
