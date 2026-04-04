#!/usr/bin/env python3
"""
SSH brute-force detector.
"""

import time
import subprocess
import select
import re
from collections import defaultdict

from modules.firewall import ensure_chain, flush_chain, block_ip, ts

CHAIN = "NIDS_BRUTEFORCE"

failures = defaultdict(list)
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


def process_line(line, cfg):
    if "Failed password" not in line:
        return

    match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
    if not match:
        return

    ip = match.group(1)
    now = time.time()

    if ip in blocked_ips:
        return

    threshold = cfg["bruteforce"]["threshold"]
    window = cfg["bruteforce"]["window_sec"]

    failures[ip].append(now)
    failures[ip] = [t for t in failures[ip] if now - t <= window]

    if len(failures[ip]) >= threshold:
        _emit(f"[ALERT] Brute force from {ip} ({len(failures[ip])} attempts in {window}s)")
        block_ip(CHAIN, ip)
        blocked_ips.add(ip)
        _emit(f"[BLOCK] Blocked {ip}")
        failures[ip].clear()


def run_detector(cfg, stop_event=None):
    """Main loop -- runs until stop_event is set."""
    failures.clear()
    blocked_ips.clear()

    ensure_chain(CHAIN)
    flush_chain(CHAIN)
    _emit("[START] Brute-force detector running")

    cmd = ["journalctl", "-u", "ssh", "-f", "-n", "0"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)

    try:
        while stop_event is None or not stop_event.is_set():
            ready, _, _ = select.select([proc.stdout], [], [], 1.0)
            if ready:
                line = proc.stdout.readline()
                if not line:
                    continue
                process_line(line, cfg)
    finally:
        proc.terminate()
        proc.wait(timeout=3)
        flush_chain(CHAIN)
        _emit("[STOP] Brute-force detector stopped")


if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from config import load_config
    run_detector(load_config())
