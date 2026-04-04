# Metasploit + NIDS — demonstration runbook

This folder ships **with** the NIDS in `nids_edit_metasploit/`. Blocking behavior matches the original project (iptables). Use only on lab networks you own or are explicitly allowed to test.

## Before every demo

1. Pick the **sniff interface** the NIDS will use: `ip -br a` (VMware often `eth0`, Wi‑Fi often `wlan0`). Set it in **Configuration** in the GUI or edit `nids_config.json` → `interface`.
2. Start the NIDS as root: `./nids.sh` from the project root.
3. For **physical** or multi‑VM labs, the traffic you generate must **cross the interface you selected**. Traffic that stays on `lo` (127.0.0.1) is usually **not** seen on `eth0`.

## Four detectors vs how you trigger them

| NIDS module   | What it watches                         | Practical trigger (this bundle) |
|---------------|-----------------------------------------|-----------------------------------|
| Port scan     | Many SYNs / ports in a short window     | `portscan_syn.rc` (Metasploit)    |
| Brute force   | SSH `Failed password` in journal      | `ssh_bruteforce.rc` + sshd on victim |
| DoS           | ICMP echo rate (tcpdump sample)       | `icmp_flood_demo.sh` (not MSF)   |
| Spoof         | ARP / bogon / TTL anomalies           | `arp_poison.rc` (Metasploit)     |
| MAC filter    | Layer‑2 allow/deny                    | Configure in GUI (whitelist/blacklist) |

Metasploit does not ship a standard “ICMP ping flood” auxiliary that matches this NIDS as cleanly as raw `ping -f`; the shell script is the reliable lab trigger for the **DoS** module.

## Metasploit resource files

Edit **IP addresses** inside each `.rc` file to match your lab, then:

```bash
msfconsole -r /home/kali/Desktop/nids_edit_metasploit/metasploit_lab/portscan_syn.rc
msfconsole -r /home/kali/Desktop/nids_edit_metasploit/metasploit_lab/ssh_bruteforce.rc
msfconsole -r /home/kali/Desktop/nids_edit_metasploit/metasploit_lab/arp_poison.rc
```

If a module’s options differ on your Metasploit version, run `use …` then `info` and `show options`.

## SSH brute-force demo (same VM possible)

1. On the **victim** (can be the same VM): `sudo ./hostbruteforce.sh` or `sudo systemctl start ssh`.
2. Set `RHOSTS` in `ssh_bruteforce.rc` to that machine’s **reachable** IP (not necessarily localhost if the NIDS sniffs `eth0`).
3. Set `USERNAME` to a real local user (e.g. `kali`). Passwords in `sample_bad_passwords.txt` are wrong on purpose so attempts fail and hit the threshold.
4. Run the resource file; watch the NIDS **Live Monitor** and expect an IP block after enough failures.

## ICMP flood (DoS module)

```bash
cd /home/kali/Desktop/nids_edit_metasploit/metasploit_lab
sudo ./icmp_flood_demo.sh <victim_ip_on_sniffed_interface>
```

Stop with Ctrl+C. Tune `dos.threshold_pps` and `dos.block_seconds` in `nids_config.json` if needed.

## Port scan

Point `RHOSTS` at the victim. Ensure the scan traffic **arrives on the monitored interface** (attacker on another host is ideal). High thread counts and wide port ranges trigger the detector faster.

## ARP poisoning

Requires a **real subnet** with distinct victim and spoofed‑identity IPs (`DHOSTS` / `SHOSTS` in `arp_poison.rc`). Run the NIDS on a host that sees the malicious ARP traffic. Adjust `INTERFACE` to the NIC attached to that LAN.

## Resetting iptables between runs (optional)

```bash
sudo ./flush_nids_iptables.sh
```

Then restart the NIDS engine from the GUI if needed.

## Path portability

If you move the project directory, update:

- `nids.desktop` → `Exec=` line  
- Metasploit `PASS_FILE` path in `ssh_bruteforce.rc` if you relocate `metasploit_lab/`

The default `logging` merge in `config.py` keeps logs under this project’s `logs/` directory automatically when you do not override `log_dir` in JSON.
