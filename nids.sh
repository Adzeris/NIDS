#!/bin/bash
# Launch NIDS GUI.
# Uses venv Python if installer/install.sh created .venv/ (run ./installer/install.sh once)

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

if [ "$EUID" -eq 0 ]; then
    exec "$PYTHON" "$SCRIPT_DIR/gui.py"
fi

# Fall back to ~/.Xauthority when XAUTHORITY is unset (common in launchers/terminals).
XAUTH="${XAUTHORITY:-$HOME/.Xauthority}"

# Allow root (the elevated process) to connect to the current user's X display.
xhost +SI:localuser:root 2>/dev/null || true

# Try privileged launch first; if policy/auth fails, fall back to non-root GUI.
if command -v pkexec &>/dev/null; then
    if pkexec env \
        DISPLAY="${DISPLAY:-:0}" \
        XAUTHORITY="$XAUTH" \
        DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-}" \
        "$PYTHON" "$SCRIPT_DIR/gui.py"; then
        exit 0
    fi
fi

# v3-like fallback: at least open the UI instead of failing silently.
if command -v xmessage &>/dev/null; then
    xmessage -center "Could not get root privileges (pkexec failed). Opening NIDS UI without root."
fi
exec "$PYTHON" "$SCRIPT_DIR/gui.py"
