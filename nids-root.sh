#!/bin/bash
# Root launcher for NIDS GUI via pkexec.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "==== $(date '+%Y-%m-%d %H:%M:%S') nids-root.sh ===="

if [ -x "$SCRIPT_DIR/.venv/bin/python3" ]; then
  PYTHON="$SCRIPT_DIR/.venv/bin/python3"
else
  PYTHON=python3
fi

# pkexec strips most of the desktop session environment. nids.sh writes the
# current values to the user's runtime dir so the auth prompt stays readable.
if [ -n "${PKEXEC_UID:-}" ]; then
  ENV_FILE="/run/user/$PKEXEC_UID/nids-launch.env"
  if [ -r "$ENV_FILE" ]; then
    # shellcheck disable=SC1090
    . "$ENV_FILE"
    export DISPLAY XAUTHORITY XDG_RUNTIME_DIR WAYLAND_DISPLAY DBUS_SESSION_BUS_ADDRESS
  fi
fi

if [ -z "${DISPLAY:-}" ]; then
  export DISPLAY=:0
fi

if [ -z "${XAUTHORITY:-}" ] && [ -n "${PKEXEC_UID:-}" ]; then
  USER_HOME="$(getent passwd "$PKEXEC_UID" | cut -d: -f6 || true)"
  if [ -n "$USER_HOME" ]; then
    export XAUTHORITY="$USER_HOME/.Xauthority"
  fi
fi

if [ -z "${WAYLAND_DISPLAY:-}" ] && [ "$EUID" -eq 0 ]; then
  export XDG_RUNTIME_DIR="${TMPDIR:-/tmp}/runtime-root"
  mkdir -p "$XDG_RUNTIME_DIR"
  chmod 700 "$XDG_RUNTIME_DIR" 2>/dev/null || true
fi

# Kali/Xfce is usually X11; force Qt to use XCB when DISPLAY is available so
# root does not accidentally try Wayland after polkit sanitizes the environment.
if [ -n "${DISPLAY:-}" ]; then
  export QT_QPA_PLATFORM="${QT_QPA_PLATFORM:-xcb}"
fi

echo "PYTHON=$PYTHON"
echo "DISPLAY=${DISPLAY:-}"
echo "XAUTHORITY=${XAUTHORITY:-}"
echo "XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-}"
echo "WAYLAND_DISPLAY=${WAYLAND_DISPLAY:-}"
echo "QT_QPA_PLATFORM=${QT_QPA_PLATFORM:-}"

exec "$PYTHON" "$SCRIPT_DIR/gui.py"
