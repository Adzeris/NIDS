
## Deliverables
+-------------------------------------------------------------+--------+--------------------------------------------------------------+
| Deliverable                                                 | Status | Notes                                                        |
+-------------------------------------------------------------+--------+--------------------------------------------------------------+
| Modular NIDS core (engine.py + modules/)                    | Done   | Threaded detectors with centralized orchestration            |
| Port-scan detection (SYN + stealth + UDP)                   | Done   | Fast and slow windows with entropy-aware scoring             |
| Brute-force detection (SSH/FTP)                             | Done   | Failure counting + IAT pattern checks                        |
| DoS/flood detection                                         | Done   | PPS thresholds + CUSUM adaptive signal                       |
| Spoof detection expansion                                   | Done   | ARP, name-service spoof, rogue DHCP, DNS spoof, TTL anomaly  |
| MAC policy enforcement                                      | Done   | Explicit blocklist with gateway MAC learning                 |
| Defender GUI (gui.py)                                       | Done   | Live logs, active blocks, advanced thresholds/toggles        |
| Attacker GUI (msp_att/metasploit_only_gui.py)               | Done   | Metasploit + generic attack launch workflow                  |
| Brute-force prep script (bruteforce_prep.sh)                | Done   | One-command defender setup for SSH brute-force testing       |
| Logging cleanup (IP first, then MAC)                        | Done   | Consistent and easier-to-read event formatting               |
+-------------------------------------------------------------+--------+--------------------------------------------------------------+

## Stretch Goals (If Time Allows)
+-------------------------------------------------------------+--------------------------------------------------------------+-----------------+
| Stretch Goal                                                | Effects                                                      | Status          |
+-------------------------------------------------------------+--------------------------------------------------------------+-----------------+
| Raspberry Pi passive sensor deployment                      | Low-cost IoT/edge deployment for real network monitoring     |                 |
| Inline IPS mode on Raspberry Pi (bridge/gateway path)       | Enable network-wide active blocking, not just host-local     |                 |
| Centralized multi-sensor dashboard                          | Aggregate alerts from multiple NIDS nodes into one view      |                 |
| SIEM/syslog export (e.g., ELK, Splunk, Wazuh)               | Makes alerts usable in enterprise-style workflows            |                 |
| Alert channels (Telegram/Discord/Email)                     | Faster incident response from live alert forwarding          |                 |
| Traffic replay evaluation mode (pcap replay)                | Repeatable benchmarking with fixed traffic captures          |                 |
| Additional protocol brute-force coverage (HTTP, SMB, RDP)   | Broader real-world attack-surface coverage                   |                 |
+-------------------------------------------------------------+--------------------------------------------------------------+-----------------+
