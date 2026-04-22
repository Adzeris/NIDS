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

- `modules/base.py`  
  Shared detector base class + shared scoring/stat helpers.

- `modules/firewall.py`  
  iptables/nftables block and unblock helper functions.

- `modules/netutil.py`  
  Network helper functions (interface IP, gateway info, trusted infra IPs).

- `modules/arpnft.py`  
  L2 ARP block helper using nftables.

- `modules/detected_mac_persist.py`  
  Saves detected MAC addresses for GUI review.

## Other Useful Files

- `bruteforce_prep.sh`  
  One-time defender setup for SSH brute-force demo testing.

- `msp_att/metasploit_only_gui.py`  
  Attacker-side launcher GUI for test traffic generation.
