# Modules Simple Guide

This is the plain-English guide to what each module does.

## Core Runtime Files

- `engine.py`  
  Starts/stops all detectors and collects their events.

- `gui.py`  
  Desktop app to start the NIDS, view alerts/blocks, and change settings.

- `config.py` and `nids_config.json`  
  Default values + your saved runtime settings.

## Detector Modules (`modules/`)

- `modules/portscan.py`  
  Catches port scans (SYN, stealth scans, UDP probes).

- `modules/bruteforce.py`  
  Catches repeated SSH/FTP login failures from the same source IP.

- `modules/dos.py`  
  Catches flood traffic (especially ICMP/SYN flood spikes).

- `modules/spoof.py`  
  Catches spoofing signals (ARP, name-service spoof, rogue DHCP, DNS spoof, TTL anomalies).

- `modules/macfilter.py`  
  Enforces explicit MAC blocklist policy.

## Support Modules (`modules/`)

- `modules/detector_base.py`  
  Shared detector base class + shared scoring/stat helpers.

- `modules/firewall.py`  
  Shared **iptables** helpers (custom chains, IP/MAC block rules). L2 netdev blocking lives in `arpnft.py`.

- `modules/host_network.py`  
  Local host network facts: interface IP/mask, subnet, default route, gateway MAC / neighbor lookup, and the trusted-infra IP set detectors use to avoid blocking gateways and whitelisted hosts.

- `modules/arpnft.py`  
  nftables **netdev ingress** blocking by source MAC (drops Ethernet before the ARP/IP stack), used when detectors choose L2 blocks.

- `modules/detected_mac_persist.py`  
  Saves detected MAC addresses for GUI review.

## Other Useful Files

- `nids.sh`  
  Desktop-friendly launcher: prefers `.venv` Python, elevation via `pkexec` + `nids-root.sh`, then runs `gui.py`.

- `nids-root.sh`  
  Small root helper invoked by polkit to run `gui.py` with correct display/Xauthority.

- `installer/install.sh`  
  One-time setup (venv, dependencies, menu shortcut, launcher path fixes).

- `bruteforce_prep.sh`  
  One-time defender setup for SSH brute-force demo testing.

Attacker-side lab tooling (e.g. Metasploit / generic attack launchers) is **not** shipped in this repo; use your own VM or lab scripts if you need offensive traffic for testing.
