#!/bin/bash
# Optional: remove NIDS iptables rules between demos (requires root).
# The GUI/engine also manage chains; use this if you need a quick manual reset.

set -euo pipefail
if [[ "$(id -u)" -ne 0 ]]; then
  exec sudo "$0" "$@"
fi

for chain in NIDS_BLOCK NIDS_SPOOF NIDS_MAC NIDS_BRUTEFORCE NIDS_DOS; do
  iptables -F "$chain" 2>/dev/null || true
  iptables -X "$chain" 2>/dev/null || true
done
echo "Attempted flush/remove of NIDS iptables chains (ignore errors if chains did not exist)."
