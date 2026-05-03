#!/usr/bin/env bash
# Started from NIDS 5.0.desktop (see Exec=...) or run directly: always lives next to nids.sh.
# Runs nids.sh via /bin/bash explicitly so file managers don't hit ENOENT on raw script exec.

set -euo pipefail

root="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
target="$root/nids.sh"

_sync_icon() {
  local src="$root/icons/nids.png"
  local dst_dir="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/48x48/apps"
  local dst="$dst_dir/nids.png"
  [[ -f "$src" ]] || return 0
  mkdir -p "$dst_dir"
  if [[ ! -f "$dst" ]] || ! cmp -s "$src" "$dst" 2>/dev/null; then
    cp -f "$src" "$dst" 2>/dev/null || true
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
      gtk-update-icon-cache -f -t "${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor" 2>/dev/null || true
    fi
  fi
}
_sync_icon

if [[ ! -f "$target" ]]; then
  msg="nids.sh not found (expected $target)"
  command -v zenity >/dev/null 2>&1 && zenity --error --text="$msg" || echo "$msg" >&2
  exit 1
fi

exec /bin/bash "$target"
