#!/usr/bin/env bash
# NIDS installer — run: ./installer/install.sh  or double-click installer/Install NIDS.desktop
set -euo pipefail

INSTALLER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$INSTALLER_DIR/.." && pwd)"
VENV="$ROOT/.venv"

echo "=============================="
echo "  NIDS Installer"
echo "=============================="
echo ""

# One desktop launcher in installer/ — runs this script next to it.
write_installer_desktop() {
  mkdir -p "$INSTALLER_DIR"
  cat > "$INSTALLER_DIR/Install NIDS.desktop" <<'EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=Install NIDS
Comment=Set up Python venv and add NIDS to your app menu.
Exec=/bin/bash -c "exec \"\\$(dirname \"\\$(readlink -f \\\"%k\\\")\")/install.sh\""
Terminal=true
Categories=Utility;
Keywords=install;nids;security;
Icon=system-software-install
EOF
  chmod +x "$INSTALLER_DIR/Install NIDS.desktop" 2>/dev/null || true
}

write_project_launcher() {
  cat > "$ROOT/NIDS 4.0.desktop" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=NIDS 4.0
Comment=Network Intrusion Detection System — Research Platform
Exec=$ROOT/nids.sh
Path=$ROOT
Icon=$ROOT/icons/nids.png
Terminal=false
Categories=Network;
Keywords=firewall;intrusion;detection;nids;
StartupNotify=false
EOF
  chmod +x "$ROOT/NIDS 4.0.desktop" 2>/dev/null || true
}

# Old layout had install at repo root; safe to remove after migration.
rm -f "$ROOT/install_nids.sh" 2>/dev/null || true

write_installer_desktop
write_project_launcher

if ! command -v python3 &>/dev/null; then
  echo "[ERROR] Python 3 is not installed."
  echo "  Run:  sudo apt install python3 python3-venv python3-pip"
  read -rp "Press Enter to exit..."
  exit 1
fi
echo "[OK] Python 3 found"

if [[ -f "$ROOT/requirements.txt" ]]; then
  echo "[...] Setting up Python environment..."
  if ! python3 -m venv --help &>/dev/null; then
    echo "[ERROR] python3-venv is missing."
    echo "  Run:  sudo apt install python3-venv"
    read -rp "Press Enter to exit..."
    exit 1
  fi
  if [[ ! -x "$VENV/bin/python3" ]]; then
    python3 -m venv "$VENV"
  fi
  "$VENV/bin/pip" install --upgrade pip -q
  if ! "$VENV/bin/pip" install -r "$ROOT/requirements.txt"; then
    echo "[ERROR] pip install failed."
    read -rp "Press Enter to exit..."
    exit 1
  fi
  echo "[OK] Dependencies installed into .venv/"
else
  echo "[WARN] requirements.txt not found — skipping dependencies"
fi

if [[ -f "$ROOT/icons/nids.png" ]]; then
  ICON_DEST="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/48x48/apps"
  mkdir -p "$ICON_DEST"
  cp -f "$ROOT/icons/nids.png" "$ICON_DEST/nids.png"
  chmod a+r "$ROOT/icons/nids.png" 2>/dev/null || true
  if command -v gtk-update-icon-cache &>/dev/null; then
    gtk-update-icon-cache -f -t "${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor" 2>/dev/null || true
  fi
fi

chmod +x "$INSTALLER_DIR/install.sh" "$ROOT/nids.sh" "$INSTALLER_DIR/Install NIDS.desktop" 2>/dev/null || true
echo "[OK] Permissions set"

VERSION="$(sed -n 's/^APP_VERSION[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$ROOT/gui.py" | head -n1)"
[[ -z "$VERSION" ]] && VERSION="4.0"

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

echo ""
echo "=============================="
echo "  Installation complete!"
echo "=============================="
echo ""
echo "  Install again: double-click installer/Install NIDS.desktop"
echo "  Run NIDS: app menu → NIDS, or double-click NIDS 4.0.desktop"
echo ""
echo "  Note: NIDS needs root for packet capture (password prompt)."
echo ""
read -rp "Press Enter to close..."
