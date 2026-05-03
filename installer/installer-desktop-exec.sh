#!/usr/bin/env bash
# Run from Install NIDS.desktop (see Exec=). Keeps install.sh next to this file; always invoke via /bin/bash.

set -euo pipefail
here="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
exec /bin/bash "$here/install.sh"
