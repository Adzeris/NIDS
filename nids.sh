#!/bin/bash
# Launch NIDS GUI.
# Uses venv Python if installer/install.sh created .venv/ (run ./installer/install.sh once)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_FILE="${TMPDIR:-/tmp}/nids-launch.log"

if [ -x "$SCRIPT_DIR/.venv/bin/python3" ]; then
  PYTHON="$SCRIPT_DIR/.venv/bin/python3"
else
  PYTHON=python3
fi

{
    echo "==== $(date '+%Y-%m-%d %H:%M:%S') nids.sh ===="
    echo "SCRIPT_DIR=$SCRIPT_DIR"
    echo "DISPLAY=${DISPLAY:-}"
    echo "XAUTHORITY=${XAUTHORITY:-}"
    echo "XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-}"
    echo "WAYLAND_DISPLAY=${WAYLAND_DISPLAY:-}"
} >>"$LOG_FILE" 2>&1

# Icon must be world-readable or the desktop session cannot load it (shows generic gear).
if [ -f "$SCRIPT_DIR/icons/nids.png" ]; then
    chmod a+r "$SCRIPT_DIR/icons/nids.png" 2>/dev/null || true
fi

if [ "$EUID" -eq 0 ]; then
    exec "$PYTHON" "$SCRIPT_DIR/gui.py"
fi

# Fall back to ~/.Xauthority when XAUTHORITY is unset (common in launchers/terminals).
XAUTH="${XAUTHORITY:-$HOME/.Xauthority}"
RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
ENV_FILE="$RUNTIME_DIR/nids-launch.env"

mkdir -p "$RUNTIME_DIR" 2>/dev/null || true
chmod 700 "$RUNTIME_DIR" 2>/dev/null || true
{
    printf 'DISPLAY=%q\n' "${DISPLAY:-}"
    printf 'XAUTHORITY=%q\n' "$XAUTH"
    printf 'XDG_RUNTIME_DIR=%q\n' "${XDG_RUNTIME_DIR:-}"
    printf 'WAYLAND_DISPLAY=%q\n' "${WAYLAND_DISPLAY:-}"
    printf 'DBUS_SESSION_BUS_ADDRESS=%q\n' "${DBUS_SESSION_BUS_ADDRESS:-}"
} >"$ENV_FILE" 2>/dev/null || true

# Allow root (the elevated process) to connect to the current user's X display.
xhost +SI:localuser:root 2>/dev/null || true

# Try privileged launch first; if policy/auth fails, fall back to non-root GUI.
if command -v pkexec &>/dev/null; then
    if pkexec /bin/bash "$SCRIPT_DIR/nids-root.sh" >>"$LOG_FILE" 2>&1; then
        exit 0
    else
        STATUS=$?
        echo "pkexec/root launch failed with status $STATUS" >>"$LOG_FILE" 2>&1
    fi
fi

# v3-like fallback: at least open the UI instead of failing silently.
if command -v xmessage &>/dev/null; then
    xmessage -center "Could not start NIDS with root privileges. Opening NIDS UI without root.\n\nDetails: $LOG_FILE"
fi
exec "$PYTHON" "$SCRIPT_DIR/gui.py" >>"$LOG_FILE" 2>&1
