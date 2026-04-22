# NIDS — Network Intrusion Detection System (v4.0)

A modular, Python-based Network Intrusion Detection System for Linux.  
Version `4.0` runs with a single adaptive detection profile focused on live lab defense: detect, alert, and block.

Project notes are available in `documentations/deliverables.md` and planning tables are in `documentations/goals.md`.

## What It Does

The system monitors traffic and host auth logs, then raises alerts and applies blocks based on module-specific signals.

## Detection Modules

| Module | Focus | Main Signal |
|--------|-------|-------------|
| **Port Scan** | TCP SYN, stealth, and UDP scan detection | Count + entropy of destination ports |
| **Brute Force** | SSH/FTP login attack detection | Failed attempt window + IAT regularity |
| **DoS / Flood** | ICMP/SYN flood detection | PPS threshold + CUSUM drift |
| **IP Spoof** | ARP/name-service/DHCP/DNS spoof detection | Multi-signal confidence + TTL anomaly scoring |
| **MAC Filter** | Explicit MAC blocklist enforcement | Policy match events |

Scan types detected: TCP SYN, Xmas, Null, FIN, ACK (stealth), UDP probes — with fast and slow detection windows.

## Runtime Features

- **Detect-only mode**: suppresses blocking so alerts do not change firewall state
- **Per-alert feature vectors** and **confidence** fields on structured events
- **Structured JSONL** and run metadata (run ID, config hash, git commit when available)
- **Consistent log formatting** with IP first, then MAC

## Architecture

```
NIDS 4.0.desktop         Double-click to launch the app (runs nids.sh). Run installer once
                           so paths/icons are correct (see installer/ below).
installer/
  install.sh               Full installer (venv, pip, menu shortcut, rewrites launchers)
  Install NIDS.desktop     Double-click runs install.sh next to it

engine.py                  Central orchestrator — starts detector threads, collects events
config.py                  Unified configuration with schema versioning
gui.py                     PyQt5 desktop interface

modules/
  base.py                  BaseDetector class + statistical utilities (entropy, Z-score, CUSUM, IAT)
  portscan.py              PortScanDetector  — entropy-augmented multi-strategy
  bruteforce.py            BruteForceDetector — IAT temporal-pattern analysis
  dos.py                   DoSDetector — CUSUM change-point detection
  spoof.py                 SpoofDetector — Z-score TTL + multi-signal confidence
  macfilter.py             MACFilterDetector — policy enforcement
  firewall.py              Shared iptables helpers
  netutil.py               Network utility functions
  arpnft.py                nftables ARP/L2 drop
  detected_mac_persist.py  MAC persistence for GUI review

```

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run with GUI (needs root for packet capture)
sudo python3 gui.py

# Or run headless
sudo python3 engine.py

# Or double-click **NIDS 4.0.desktop** after ./installer/install.sh once (see Desktop launchers below)
```

### Desktop launchers

| File | Purpose |
|------|---------|
| **`NIDS 4.0.desktop`** (repo root) | Double-click to **start NIDS** (`nids.sh`). |
| **`installer/Install NIDS.desktop`** | Double-click to **run the installer** (venv + menu shortcut). |

**One-time setup** (venv + correct icon + rewritten `NIDS 4.0.desktop`):
```bash
chmod +x installer/install.sh nids.sh
./installer/install.sh
```

On **GNOME**, if double-click does nothing, right-click the `.desktop` → **Allow launching**.

**Run NIDS manually:** `./nids.sh`  
**Install manually:** `./installer/install.sh` (or double-click `installer/Install NIDS.desktop`)

## Evaluation Note

- GUI: `sudo python3 gui.py`
- Headless: `sudo python3 engine.py`

## Requirements

- Python 3.10+, PyQt5, Scapy
- Linux with iptables (root privileges required for packet capture)
- Optional: nftables for L2 ARP drop

## Author

MD Saadman Kabir — ID: 25502701
