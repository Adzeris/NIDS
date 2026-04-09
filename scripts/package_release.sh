#!/usr/bin/env bash
# Build a clean source zip for GitHub Releases (tracked files only).
# Run from repo root: ./scripts/package_release.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="$(grep -E '^APP_VERSION\s*=' gui.py | sed -n 's/.*=\s*"\([^"]*\)".*/\1/p')"
if [[ -z "${VERSION}" ]]; then
  echo "Could not read APP_VERSION from gui.py" >&2
  exit 1
fi

OUT_DIR="$ROOT/dist"
mkdir -p "$OUT_DIR"
OUT_ZIP="$OUT_DIR/nids-${VERSION}-source.zip"

if ! command -v git &>/dev/null; then
  echo "git is required for git archive" >&2
  exit 1
fi

if ! git rev-parse --git-dir &>/dev/null; then
  echo "Not a git repository" >&2
  exit 1
fi

git archive --format=zip --prefix="nids-${VERSION}/" -o "$OUT_ZIP" HEAD
echo "Created: $OUT_ZIP"
echo "Upload this file to a GitHub Release (e.g. tag v${VERSION})."
