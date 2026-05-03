#!/usr/bin/env bash
# Install the lightweight NIDS IoT endpoint agent on a Linux device.
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "[ERROR] Run as root: sudo ./agent/install-agent.sh"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/nids-agent"
CONFIG_DIR="/etc/nids-agent"
LOG_DIR="/var/log/nids-agent"
SERVICE_SRC="$SCRIPT_DIR/systemd/nids-agent.service"
SERVICE_DST="/etc/systemd/system/nids-agent.service"

echo "Installing NIDS IoT endpoint agent..."

if ! command -v python3 >/dev/null 2>&1; then
  echo "[ERROR] python3 is required."
  exit 1
fi

mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"
cp -f "$SCRIPT_DIR/nids-agent.py" "$INSTALL_DIR/nids-agent.py"
chmod +x "$INSTALL_DIR/nids-agent.py"

if [[ ! -f "$CONFIG_DIR/agent_config.json" ]]; then
  cp -f "$SCRIPT_DIR/agent_config.json" "$CONFIG_DIR/agent_config.json"
  echo "[OK] Created $CONFIG_DIR/agent_config.json"
else
  echo "[OK] Keeping existing $CONFIG_DIR/agent_config.json"
fi

chmod 755 "$INSTALL_DIR"
chmod 755 "$LOG_DIR"

if command -v systemctl >/dev/null 2>&1 && [[ -d /etc/systemd/system ]]; then
  cp -f "$SERVICE_SRC" "$SERVICE_DST"
  systemctl daemon-reload
  systemctl enable nids-agent.service
  systemctl restart nids-agent.service
  echo "[OK] systemd service enabled and started"
  echo "     Status: sudo systemctl status nids-agent"
else
  echo "[WARN] systemd not found. Start manually with:"
  echo "      python3 $INSTALL_DIR/nids-agent.py --config $CONFIG_DIR/agent_config.json"
fi

echo "[DONE] NIDS IoT endpoint agent installed."
