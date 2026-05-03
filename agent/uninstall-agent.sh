#!/usr/bin/env bash
# Remove the NIDS IoT endpoint agent from a Linux device.
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "[ERROR] Run as root: sudo ./agent/uninstall-agent.sh"
  exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl stop nids-agent.service 2>/dev/null || true
  systemctl disable nids-agent.service 2>/dev/null || true
  rm -f /etc/systemd/system/nids-agent.service
  systemctl daemon-reload 2>/dev/null || true
fi

rm -rf /opt/nids-agent

echo "[OK] Removed agent service and /opt/nids-agent"
echo "Config/logs kept by default:"
echo "  /etc/nids-agent"
echo "  /var/log/nids-agent"
