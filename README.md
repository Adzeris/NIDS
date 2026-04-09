# NIDS — A Custom made Network Intrusion Detection System

My program is a Python-based Network Intrusion Detection System that monitors network traffic in real time and blocks them, also offering to block the MAC addresses of the attacker.

This version is an update of my original work which has been tested to work on metasploit in Kali Linux. 

## What It Does

This program watches your network interface for common attacks and automatically blocks the attacker's IP or MAC address. 

It has four detection modules:
- **Port Scan Detector** — Catches TCP SYN scans (like nmap) by tracking how many unique ports a single IP hits in a short time window. Uses Scapy for packet sniffing.
- **Brute-Force Detector** — Monitors SSH login attempts through system logs (journalctl). If someone fails too many times in a row, they get blocked.
- **DoS Detector** — Samples ICMP traffic using tcpdump and blocks any source flooding you with ping requests above a threshold.
- **Spoof Detector** — Detects ARP spoofing (MitM attacks), bogon/fake source IPs, and TTL anomalies that suggest someone is intercepting traffic.

There is also a **MAC Address Filter** that supports whitelist and blacklist modes, and a detected MAC review system where blocked MACs are saved for you to decide what to do with them later.

## How It Works
- Each module runs in its own thread
- Blocking is done through custom iptables chains (`NIDS_PORTSCAN`, `NIDS_BRUTEFORCE`, `NIDS_DOS`, `NIDS_SPOOF`, `NIDS_MACFILTER`)
- All settings (thresholds, enabled modules, interface, etc.) are saved in `nids_config.json`
- Logs are saved to the `logs/` folder with timestamps

## Requirements
- Python 3, PyQt5, Scapy, Linux with iptables, Root privileges (needed for packet capture and firewall rules)


## Installation

Download and extract the project
Double-click install_nids_menu.desktop (or run ./install_desktop.sh from a terminal)
Open your app menu and search for NIDS
NIDS will ask for your password (it needs root for packet capture)

## How to Run / Prerequisites

```bash
# Install dependencies
pip install -r requirements.txt

# Run with the launcher (auto-elevates to root)
./nids.sh

# Or run directly
sudo python3 gui.py
```

## GUI

The GUI has four tabs:

- **Live Monitor** — Shows real-time alerts, blocks, and system messages
- **Configuration** — Set the network interface, enable/disable modules, and adjust detection thresholds
- **MAC Filter** — Manage allowed/blocked MAC addresses and review detected MACs
- **About** — Basic info about the program

## Files

| File | Description |
|------|-------------|
| `gui.py` | PyQt5 desktop interface |
| `engine.py` | Core engine that starts and manages all detector threads |
| `config.py` | Handles loading and saving configuration |
| `nids_config.json` | User configuration file |
| `modules/portscan.py` | Port scan detection |
| `modules/bruteforce.py` | SSH brute-force detection |
| `modules/dos.py` | ICMP flood detection |
| `modules/spoof.py` | ARP spoof / bogon / TTL anomaly detection |
| `modules/macfilter.py` | MAC address filtering |
| `modules/firewall.py` | Shared iptables helper functions |
| `modules/netutil.py` | Network utility functions (IP, subnet, gateway) |
| `modules/detected_mac_persist.py` | Saves detected MACs into nids_config.json |
| `modules/arpnft.py` | Optional nftables ARP drop (used with spoof blocking) |


## Metasploit extras

| Path | Purpose |
|------|---------|
| `metasploit_lab/RUNBOOK.md` | Demo order, interface notes, same‑VM vs physical LAN |
| `metasploit_lab/portscan_syn.rc` | SYN scan auxiliary (port-scan detector) |
| `metasploit_lab/ssh_bruteforce.rc` | SSH scanner (brute-force detector) |
| `metasploit_lab/arp_poison.rc` | ARP poisoning auxiliary (spoof detector) |
| `metasploit_lab/icmp_flood_demo.sh` | ICMP flood (DoS detector — complements MSF) |
| `metasploit_lab/sample_bad_passwords.txt` | Wrong passwords for SSH demo |
| `metasploit_lab/flush_nids_iptables.sh` | Optional iptables cleanup between runs |

**Physical vs VM:** set `interface` in the GUI/`nids_config.json` to the NIC that actually carries your attack traffic (`eth0`, `wlan0`, etc.). Traffic confined to `lo` is usually invisible to an `eth0` sniffer.

## Built For

This was built and tested on Kali Linux running in a VMware virtual machine; the same code paths apply on physical hardware when the correct interface is selected.

## UI

<img width="1657" height="994" alt="2 1" src="https://github.com/user-attachments/assets/23fd040f-a430-426b-823c-9452175e0e2a" />

