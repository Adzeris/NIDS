#!/usr/bin/env python3
"""
Brute-force detector — SSH (journalctl) + FTP (auth log / vsftpd log).
Both watchers feed into a shared per-IP failure tracker with independent
thresholds per service.
"""

import time
import subprocess
import select
import re
import os
import threading
from collections import defaultdict

from modules.firewall import ensure_chain, flush_chain, block_ip, ts
from modules.netutil import get_default_gateway

CHAIN = "NIDS_BRUTEFORCE"

failures_ssh = defaultdict(list)
failures_ftp = defaultdict(list)
blocked_ips = set()
_safe_ips = set()
stats = {"ssh_lines": 0, "ftp_lines": 0, "blocks": 0}

_callback = None
_lock = threading.Lock()


def set_callback(fn):
    global _callback
    _callback = fn


def _emit(msg):
    line = f"{ts()} {msg}"
    if _callback:
        _callback(line)
    else:
        print(line, flush=True)


def _try_block(ip, service, count, window):
    with _lock:
        if ip in blocked_ips or ip in _safe_ips:
            return
        _emit(f"[ALERT] {service} brute force from {ip} ({count} attempts in {window}s)")
        block_ip(CHAIN, ip)
        blocked_ips.add(ip)
        stats["blocks"] += 1
        _emit(f"[BLOCK] Blocked {ip}")


# ---- SSH watcher ---------------------------------------------------------

_SSH_IP_RE = re.compile(r'from (\d+\.\d+\.\d+\.\d+)')

def _process_ssh_line(line, cfg):
    stats["ssh_lines"] += 1
    if "Failed password" not in line:
        return

    m = _SSH_IP_RE.search(line)
    if not m:
        return

    ip = m.group(1)
    now = time.time()

    if ip in blocked_ips or ip in _safe_ips:
        return

    threshold = cfg["bruteforce"]["threshold"]
    window = cfg["bruteforce"]["window_sec"]

    failures_ssh[ip].append(now)
    failures_ssh[ip] = [t for t in failures_ssh[ip] if now - t <= window]

    if len(failures_ssh[ip]) >= threshold:
        _try_block(ip, "SSH", len(failures_ssh[ip]), window)
        failures_ssh[ip].clear()


def _ssh_watcher(cfg, stop_event):
    cmd = ["journalctl", "-u", "ssh", "-f", "-n", "0"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)

    try:
        while stop_event is None or not stop_event.is_set():
            ready, _, _ = select.select([proc.stdout], [], [], 1.0)
            if ready:
                line = proc.stdout.readline()
                if not line:
                    continue
                _process_ssh_line(line, cfg)
    finally:
        proc.terminate()
        proc.wait(timeout=3)


# ---- FTP watcher ---------------------------------------------------------

_FTP_FAIL_PATTERNS = [
    re.compile(r'FAIL LOGIN.*?(?:client\s+\"?)(\d+\.\d+\.\d+\.\d+)'),
    re.compile(r'vsftpd.*authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)'),
    re.compile(r'proftpd.*no such user.*?\[(\d+\.\d+\.\d+\.\d+)\]'),
    re.compile(r'proftpd.*Login failed.*?\[(\d+\.\d+\.\d+\.\d+)\]'),
    re.compile(r'pam_unix\(.*ftpd.*\).*authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)'),
    re.compile(r'pure-ftpd.*Authentication failed.*?(\d+\.\d+\.\d+\.\d+)'),
    re.compile(r'Unable to Connect.*?(\d+\.\d+\.\d+\.\d+)'),
]

_FTP_LOG_PATHS = [
    "/var/log/vsftpd.log",
    "/var/log/auth.log",
    "/var/log/proftpd/proftpd.log",
    "/var/log/syslog",
]


def _process_ftp_line(line, cfg):
    stats["ftp_lines"] += 1

    ip = None
    for pat in _FTP_FAIL_PATTERNS:
        m = pat.search(line)
        if m:
            ip = m.group(1)
            break

    if not ip:
        return

    now = time.time()
    if ip in blocked_ips or ip in _safe_ips:
        return

    threshold = cfg["bruteforce"].get("ftp_threshold", 5)
    window = cfg["bruteforce"].get("ftp_window_sec", 60)

    failures_ftp[ip].append(now)
    failures_ftp[ip] = [t for t in failures_ftp[ip] if now - t <= window]

    if len(failures_ftp[ip]) >= threshold:
        _try_block(ip, "FTP", len(failures_ftp[ip]), window)
        failures_ftp[ip].clear()


def _ftp_watcher(cfg, stop_event):
    log_path = None
    for p in _FTP_LOG_PATHS:
        if os.path.exists(p):
            log_path = p
            break

    if not log_path:
        _emit("[INFO] FTP brute-force: no FTP log found, using journalctl fallback")
        cmd = ["journalctl", "-t", "vsftpd", "-t", "proftpd", "-t", "pure-ftpd", "-f", "-n", "0"]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        try:
            while stop_event is None or not stop_event.is_set():
                ready, _, _ = select.select([proc.stdout], [], [], 1.0)
                if ready:
                    line = proc.stdout.readline()
                    if line:
                        _process_ftp_line(line, cfg)
        finally:
            proc.terminate()
            proc.wait(timeout=3)
        return

    _emit(f"[INFO] FTP brute-force: monitoring {log_path}")
    cmd = ["tail", "-F", "-n", "0", log_path]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

    try:
        while stop_event is None or not stop_event.is_set():
            ready, _, _ = select.select([proc.stdout], [], [], 1.0)
            if ready:
                line = proc.stdout.readline()
                if line:
                    _process_ftp_line(line, cfg)
    finally:
        proc.terminate()
        proc.wait(timeout=3)


# ---- Main entry point ----------------------------------------------------

def _build_safe_ips(cfg, iface):
    safe = {"0.0.0.0", "255.255.255.255"}
    gw = get_default_gateway(iface)
    if gw and cfg.get("spoof", {}).get("gateway_auto_whitelist", True):
        safe.add(gw)
    if cfg.get("spoof", {}).get("whitelist_host") and cfg.get("spoof", {}).get("host_ip", "").strip():
        safe.add(cfg["spoof"]["host_ip"].strip())
    for ip_str in cfg.get("spoof", {}).get("whitelist_ips", []):
        safe.add(ip_str.strip())
    return safe


def run_detector(cfg, stop_event=None):
    """Start SSH + FTP watchers. Runs until stop_event is set."""
    global _safe_ips
    failures_ssh.clear()
    failures_ftp.clear()
    blocked_ips.clear()
    _safe_ips = _build_safe_ips(cfg, cfg["interface"])
    stats["ssh_lines"] = 0
    stats["ftp_lines"] = 0
    stats["blocks"] = 0

    ensure_chain(CHAIN)
    flush_chain(CHAIN)
    _emit("[START] Brute-force detector running (SSH + FTP)")

    ftp_thread = threading.Thread(
        target=_ftp_watcher, args=(cfg, stop_event),
        daemon=True, name="nids-bf-ftp",
    )
    ftp_thread.start()

    try:
        _ssh_watcher(cfg, stop_event)
    finally:
        if stop_event:
            stop_event.set()
        ftp_thread.join(timeout=4)
        flush_chain(CHAIN)
        _emit("[STOP] Brute-force detector stopped")


if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from config import load_config
    run_detector(load_config())
