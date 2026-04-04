#!/bin/bash
# Launch NIDS GUI with root privileges (needed for iptables/scapy).
# Make executable:  chmod +x nids.sh
# Then double-click or run:  ./nids.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ "$EUID" -ne 0 ]; then
    # Re-launch with pkexec (graphical sudo prompt) or sudo
    if command -v pkexec &>/dev/null; then
        exec pkexec env DISPLAY="$DISPLAY" XAUTHORITY="$XAUTHORITY" \
            python3 "$SCRIPT_DIR/gui.py"
    else
        exec sudo python3 "$SCRIPT_DIR/gui.py"
    fi
else
    exec python3 "$SCRIPT_DIR/gui.py"
fi
