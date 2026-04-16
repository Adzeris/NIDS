#!/bin/bash
# ICMP echo flood — exercises the NIDS DoS (ICMP) detector. Run as root.
# Metasploit has few reliable generic "ping flood" modules; this matches what dos.py watches (tcpdump icmp).
#
# Usage:
#   sudo ./icmp_flood_demo.sh <target_ip>
#
# Use the victim's address on the interface your NIDS is sniffing (often your VM's eth0 IP, not 127.0.0.1).

set -euo pipefail
TARGET="${1:?Usage: $0 <target_ip>}"
echo "Flooding ICMP echo to $TARGET — Ctrl+C to stop. NIDS threshold is in nids_config.json (dos.threshold_pps)."
exec ping -f -s 56 "$TARGET"
