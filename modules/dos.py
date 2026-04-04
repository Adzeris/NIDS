#!/usr/bin/env python3
"""
ICMP flood / DoS detector.
"""

import subprocess
import time
import re
from collections import defaultdict

from modules.firewall import ensure_chain, flush_chain, block_ip, ts

CHAIN = "NIDS_DOS"
blocked_ips = set()

_callback = None


def set_callback(fn):
    global _callback
    _callback = fn


def _emit(msg):
    line = f"{ts()} {msg}"
    if _callback:
        _callback(line)
    else:
        print(line, flush=True)


def count_icmp_by_source(iface):
    cmd = ["sudo", "timeout", "1", "tcpdump", "-n", "-i", iface, "icmp"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    counts = defaultdict(int)

    for line in proc.stdout.splitlines():
        m = re.search(r'IP\s+(\d+\.\d+\.\d+\.\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+):', line)
        if not m:
            continue
        if "ICMP echo request" not in line:
            continue
        counts[m.group(1)] += 1

    return counts


def run_detector(cfg, stop_event=None):
    """Main loop -- runs until stop_event is set."""
    blocked_ips.clear()

    iface = cfg["interface"]
    threshold = cfg["dos"]["threshold_pps"]

    ensure_chain(CHAIN)
    flush_chain(CHAIN)
    _emit("[START] DoS detector running")

    try:
        while stop_event is None or not stop_event.is_set():
            counts = count_icmp_by_source(iface)

            for src_ip, pps in counts.items():
                if src_ip in blocked_ips:
                    continue
                if pps > threshold:
                    _emit(f"[ALERT] DoS flood from {src_ip}: {pps} pps")
                    block_ip(CHAIN, src_ip)
                    blocked_ips.add(src_ip)
                    _emit(f"[BLOCK] Blocked {src_ip}")
    finally:
        flush_chain(CHAIN)
        _emit("[STOP] DoS detector stopped")


if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from config import load_config
    run_detector(load_config())
