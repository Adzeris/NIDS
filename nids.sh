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
    # Fall back to ~/.Xauthority when XAUTHORITY is unset (common in launchers/terminals).
    XAUTH="${XAUTHORITY:-$HOME/.Xauthority}"

    # Allow root (the elevated process) to connect to the current user's X display.
    xhost +SI:localuser:root 2>/dev/null || true

    if command -v pkexec &>/dev/null; then
        exec pkexec env \
            DISPLAY="$DISPLAY" \
            XAUTHORITY="$XAUTH" \
            DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-}" \
            "$PYTHON" "$SCRIPT_DIR/gui.py"
    else
        exec sudo -E \
            DISPLAY="$DISPLAY" \
            XAUTHORITY="$XAUTH" \
            "$PYTHON" "$SCRIPT_DIR/gui.py"
    fi
else
    exec "$PYTHON" "$SCRIPT_DIR/gui.py"
fi
