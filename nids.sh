#!/bin/bash
# Launch NIDS GUI with root privileges (needed for iptables/scapy).
# Uses venv Python if ./installer created .venv/

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -x "$SCRIPT_DIR/.venv/bin/python3" ]; then
  PYTHON="$SCRIPT_DIR/.venv/bin/python3"
else
  PYTHON=python3
fi

# Icon must be world-readable or the desktop session cannot load it (shows generic gear).
if [ -f "$SCRIPT_DIR/icons/nids.png" ]; then
    chmod a+r "$SCRIPT_DIR/icons/nids.png" 2>/dev/null || true
fi

if [ "$EUID" -ne 0 ]; then
    if command -v pkexec &>/dev/null; then
        exec pkexec env DISPLAY="$DISPLAY" XAUTHORITY="$XAUTHORITY" \
            "$PYTHON" "$SCRIPT_DIR/gui.py"
    else
        exec sudo "$PYTHON" "$SCRIPT_DIR/gui.py"
    fi
else
    exec "$PYTHON" "$SCRIPT_DIR/gui.py"
fi
