# NIDS — Deliverables & Project Log

**Author:** MD Saadman Kabir  
**ID:** 25502701  
**Current Version:** v5.0

---

## Version History

### v1.0 — Initial Prototype
- Basic NIDS skeleton with packet capture via Scapy
- Early port scan and ARP spoof detection (fixed thresholds only)
- No GUI, no config file, no firewall integration
- Single-file structure

### v2.0 — Module Restructure & GUI
- Split detectors into separate module files (`portscan.py`, `spoof.py`, etc.)
- First working PyQt5 GUI with live log output
- Fixed portscan and spoof detection bugs from v1
- Basic iptables block/unblock integration

### v3.0 — Engineering Prototype
- Added network mode selection (NAT / Bridged)
- Stealth scan detection (Xmas, Null, FIN, ACK) alongside SYN scan
- Desktop launcher and one-command installer (`installer/install.sh`)
- Slow-scan detection window (separate threshold for low-and-slow patterns)
- GUI crash fixes for fresh installations

### v4.0 — Adaptive Detection Platform
- Unified adaptive detection method across all modules (entropy, CUSUM, Z-score, IAT)
- Expanded spoof detector: ARP reply burst, LLMNR/mDNS/NBNS spoof, Rogue DHCP, DNS spoof
- Gateway auto-whitelisting with `whitelist_default_gateway` config option
- Local-sources-only filter for port scan (ignores public internet noise)
- Per-alert confidence scoring and structured feature vectors on all events
- One-time notification for whitelisted IPs (no repeated spam)
- MAC filter simplified to explicit blocklist with dynamic gateway MAC learning
- Full Advanced Settings panel in GUI for all detection thresholds and toggles
- Attacker GUI (`msp_att/`) with Metasploit and generic attack tools
- `bruteforce_prep.sh` one-command SSH setup for brute-force testing
- Cleaned, consistent log message format (IP always before MAC)

### v5.0 — Current: IoT-Aware NIDS Foundation
- Renamed project/application version to v5.0
- Added passive IoT device profiling module (`modules/iot_profile.py`)
- Added IoT/LAN device inventory logging for newly observed devices
- Added scan-like IoT behavior alerting based on destination-port fanout
- Added GUI module toggle and config defaults for IoT profiling
- Added lightweight installable IoT endpoint agent (`agent/nids-agent.py`)
- Added systemd installer/uninstaller for Linux-based IoT devices
- Added local JSONL event logging and optional controller POST support for endpoint devices

---

## Completed Deliverables

### Detection Modules

| Module | What it detects | Key method |
|--------|----------------|------------|
| `modules/portscan.py` | TCP SYN, Stealth (Xmas/Null/FIN/ACK), UDP scans — fast and slow windows | Port count + Shannon entropy of destination-port distribution |
| `modules/bruteforce.py` | SSH and FTP login brute-force | Failure count + inter-arrival time regularity (low IAT variance = automated tool) |
| `modules/dos.py` | ICMP and TCP SYN flood | Packets-per-second threshold + CUSUM change-point detection |
| `modules/spoof.py` | ARP poisoning, ARP reply burst, LLMNR/mDNS/NBNS spoof, Rogue DHCP, DNS spoof, Bogon IPs, TTL anomaly | Multi-signal confidence scoring with Z-score TTL modelling |
| `modules/macfilter.py` | Explicitly blocked MAC addresses | Blocklist policy with dynamic gateway MAC learning |
| `modules/iot_profile.py` | Passive IoT/LAN device inventory and scan-like fanout hints | Device profiling + destination-port fanout |

### Supporting Infrastructure

| File | Role |
|------|------|
| `modules/detector_base.py` | `BaseDetector` abstract class, `DetectionEvent` structure, shared statistical utilities (entropy, Z-score, CUSUM, IAT) |
| `modules/firewall.py` | iptables chain management, block/unblock helpers |
| `modules/host_network.py` | Interface IP lookup, gateway resolution, trusted infrastructure IP collection |
| `modules/arpnft.py` | nftables L2 ARP drop rules |
| `modules/detected_mac_persist.py` | Persists detected MACs to GUI review panel |
| `engine.py` | Central orchestrator — starts detector threads, collects events, manages lifecycle |
| `config.py` | Unified configuration schema with defaults for all modules |
| `gui.py` | PyQt5 desktop application — live log, active blocks panel, full config editor |

### Lab Tooling

| File | Role |
|------|------|
| `bruteforce_prep.sh` | One-command SSH + test user setup on defender VM for brute-force testing |
| `msp_att/metasploit_only_gui.py` | Unified attacker GUI — Metasploit and generic attack tools (Nmap, hping3, Scapy, Hydra) |
| `msp_att/bruteforce_db.json` | Brute-force attack profiles with username/password lists |

### IoT Endpoint Agent

| File | Role |
|------|------|
| `agent/nids-agent.py` | Lightweight stdlib-only Linux agent for IoT/Raspberry Pi-style endpoints |
| `agent/agent_config.json` | Agent ID, thresholds, local log path, and optional controller URL |
| `agent/install-agent.sh` | Installs the endpoint agent to `/opt/nids-agent` and enables systemd service |
| `agent/uninstall-agent.sh` | Removes the systemd service and installed agent files |
| `agent/systemd/nids-agent.service` | systemd unit for boot-time endpoint monitoring |

---

## Architecture

```
engine.py                   Central orchestrator
config.py / nids_config.json  Unified configuration
gui.py                      PyQt5 desktop interface

modules/
  detector_base.py          BaseDetector + statistical utilities
  portscan.py               Port scan — entropy-augmented, fast + slow windows
  bruteforce.py             Brute force — failure count + IAT analysis (SSH + FTP)
  dos.py                    DoS flood — threshold + CUSUM
  spoof.py                  Spoof — ARP, LLMNR, mDNS, NBNS, DHCP, DNS, TTL, Bogon
  macfilter.py              MAC filter — explicit blocklist
  iot_profile.py            IoT profile — passive inventory and behavior hints
  firewall.py               iptables / nftables helpers
  host_network.py           Local network facts and trusted IP resolution
  arpnft.py                 nftables ARP drop
  detected_mac_persist.py   MAC persistence for GUI

msp_att/                    Attacker-side tools (separate VM)
  metasploit_only_gui.py    Unified attack GUI
  bruteforce_db.json        Brute-force credential profiles
  generated_wordlists/      Auto-generated wordlist files

agent/                     Optional installable IoT endpoint agent
  nids-agent.py             Local endpoint monitoring
  install-agent.sh          Linux/systemd installer
  agent_config.json         Agent configuration

documentations/
  deliverables.md           Completed work log
  goals.md                  Deliverables and stretch goals tables
  modules-simple-guide.md   Plain-English module explainer
```

---

## Requirements

- Python 3.10+, PyQt5, Scapy
- Linux with iptables (root required for packet capture)
- Optional: nftables for L2 ARP blocking
