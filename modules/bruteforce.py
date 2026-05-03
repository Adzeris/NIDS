#!/usr/bin/env python3
"""
Brute-force detector v2.0 — temporal-pattern-augmented authentication attack detection.

Detection strategies:
  Count + timing regularity: alert on threshold breach, and additionally use
  inter-arrival regularity to catch scripted automation earlier.

Services: SSH (journalctl) + FTP (auth/vsftpd/proftpd logs).

Research features:
  - Per-alert feature vectors (failure_count, mean_iat, cv_iat, burst_score, ...)
  - Confidence scoring
  - Detect-only mode
"""

import time
import subprocess
import select
import re
import os
import threading
from collections import defaultdict

from modules.detector_base import BaseDetector, inter_arrival_times, rolling_stats
from modules.firewall import ensure_chain, flush_chain, block_ip, ts
from modules.host_network import collect_trusted_infrastructure_ips


class BruteForceDetector(BaseDetector):

    NAME = 'bruteforce'
    VERSION = '2.0'
    CHAIN = 'NIDS_BRUTEFORCE'

    _SSH_IP_RE = re.compile(r'from (\d+\.\d+\.\d+\.\d+)')
    _FTP_FAIL_PATTERNS = [
        re.compile(r'FAIL LOGIN.*?(?:client\s+"?)(\d+\.\d+\.\d+\.\d+)'),
        re.compile(r'vsftpd.*authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)'),
        re.compile(r'proftpd.*no such user.*?\[(\d+\.\d+\.\d+\.\d+)\]'),
        re.compile(r'proftpd.*Login failed.*?\[(\d+\.\d+\.\d+\.\d+)\]'),
        re.compile(r'pam_unix\(.*ftpd.*\).*authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)'),
        re.compile(r'pure-ftpd.*Authentication failed.*?(\d+\.\d+\.\d+\.\d+)'),
        re.compile(r'Unable to Connect.*?(\d+\.\d+\.\d+\.\d+)'),
    ]
    _FTP_LOG_PATHS = [
        "/var/log/vsftpd.log", "/var/log/auth.log",
        "/var/log/proftpd/proftpd.log", "/var/log/syslog",
    ]

    def __init__(self, cfg, stop_event, log_callback=None):
        super().__init__(cfg, stop_event, log_callback)

        self.failures_ssh = defaultdict(list)  # ip -> [timestamps]
        self.failures_ftp = defaultdict(list)
        self.blocked_ips = set()
        self._safe_ips = set()
        self._safe_ip_notified = set()
        self._block_lock = threading.Lock()

        self.stats = {'ssh_lines': 0, 'ftp_lines': 0, 'blocks': 0}

    # -- safe-IP logic -----------------------------------------------------

    def _build_safe_ips(self):
        return collect_trusted_infrastructure_ips(self.cfg, self.cfg['interface'])

    # -- feature extraction ------------------------------------------------

    def _iat_features(self, timestamps, service):
        """Summarize timing regularity for repeated authentication failures."""
        iats = inter_arrival_times(sorted(timestamps))
        if not iats:
            return {'service': service, 'iat_count': 0}

        mean_iat, std_iat = rolling_stats(iats)
        # Lower coefficient of variation means more regular spacing, which is a
        # useful signature for scripted brute-force tools.
        cv_iat = std_iat / mean_iat if mean_iat > 0 else 0.0
        min_iat = min(iats)
        failure_rate = len(timestamps) / max(timestamps[-1] - timestamps[0], 0.01)

        return {
            'service': service,
            'failure_count': len(timestamps),
            'iat_count': len(iats),
            'mean_iat': round(mean_iat, 4),
            'std_iat': round(std_iat, 4),
            'cv_iat': round(cv_iat, 4),
            'min_iat': round(min_iat, 4),
            'failure_rate': round(failure_rate, 2),
        }

    def _confidence(self, feat, threshold, window):
        c_count = min(1.0, feat.get('failure_count', 0) / max(threshold, 1))

        if feat.get('iat_count', 0) >= 2:
            # Low CV = regular spacing = automated tool = higher confidence
            cv = feat.get('cv_iat', 1.0)
            c_automation = max(0.0, 1.0 - cv) if cv < 1.5 else 0.0
            conf = 0.60 * c_count + 0.40 * c_automation
        else:
            conf = c_count
        return round(min(1.0, conf), 4)

    # -- shared alert/block ------------------------------------------------

    def _try_block(self, ip, service, timestamps, threshold, window):
        with self._block_lock:
            if ip in self.blocked_ips:
                return

            feat = self._iat_features(timestamps, service)
            conf = self._confidence(feat, threshold, window)
            feat['confidence'] = conf

            triggered = len(timestamps) >= threshold
            if not triggered:
                # Early trigger for highly regular automated attempts.
                triggered = (len(timestamps) >= max(threshold // 2, 3)
                             and conf >= 0.75
                             and feat.get('cv_iat', 1.0) < 0.3)

            if not triggered:
                return

            msg = (f"{service} brute force from {ip} "
                   f"({feat['failure_count']} attempts in {window}s"
                   f", cv_iat={feat.get('cv_iat', 'N/A')})")
            self.alert(message=msg, source_ip=ip, confidence=conf,
                       features=feat)

            if ip in self._safe_ips:
                if ip not in self._safe_ip_notified:
                    self.warn(f"{ip} is whitelisted (gateway) — logged once, will not repeat")
                    self._safe_ip_notified.add(ip)
            else:
                blocked = self.block(
                    target=ip, reason=f"{service} brute force",
                    source_ip=ip, confidence=conf, features=feat,
                    do_block_fn=lambda: block_ip(self.CHAIN, ip),
                )
                if blocked:
                    self.blocked_ips.add(ip)
                    self.stats['blocks'] += 1

    # -- SSH watcher -------------------------------------------------------

    def _process_ssh_line(self, line):
        self.stats['ssh_lines'] += 1
        if 'Failed password' not in line:
            return

        m = self._SSH_IP_RE.search(line)
        if not m:
            return

        ip = m.group(1)
        now = time.time()
        if ip in self.blocked_ips:
            return

        threshold = self.cfg['bruteforce']['threshold']
        window = self.cfg['bruteforce']['window_sec']

        self.failures_ssh[ip].append(now)
        self.failures_ssh[ip] = [t for t in self.failures_ssh[ip]
                                 if now - t <= window]

        self._try_block(ip, 'SSH', self.failures_ssh[ip], threshold, window)
        if ip in self.blocked_ips:
            self.failures_ssh[ip].clear()

    def _ssh_watcher(self):
        cmd = ["journalctl", "-u", "ssh", "-f", "-n", "0"]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
        try:
            while not self.stop_event.is_set():
                ready, _, _ = select.select([proc.stdout], [], [], 1.0)
                if ready:
                    line = proc.stdout.readline()
                    if line:
                        self._process_ssh_line(line)
        finally:
            proc.terminate()
            proc.wait(timeout=3)

    # -- FTP watcher -------------------------------------------------------

    def _process_ftp_line(self, line):
        self.stats['ftp_lines'] += 1
        ip = None
        for pat in self._FTP_FAIL_PATTERNS:
            m = pat.search(line)
            if m:
                ip = m.group(1)
                break
        if not ip:
            return

        now = time.time()
        if ip in self.blocked_ips:
            return

        threshold = self.cfg['bruteforce'].get('ftp_threshold', 5)
        window = self.cfg['bruteforce'].get('ftp_window_sec', 60)

        self.failures_ftp[ip].append(now)
        self.failures_ftp[ip] = [t for t in self.failures_ftp[ip]
                                 if now - t <= window]

        self._try_block(ip, 'FTP', self.failures_ftp[ip], threshold, window)
        if ip in self.blocked_ips:
            self.failures_ftp[ip].clear()

    def _ftp_watcher(self):
        log_path = None
        for p in self._FTP_LOG_PATHS:
            if os.path.exists(p):
                log_path = p
                break

        if not log_path:
            self.info("FTP brute-force: no FTP log found, using journalctl fallback")
            cmd = ["journalctl", "-t", "vsftpd", "-t", "proftpd",
                   "-t", "pure-ftpd", "-f", "-n", "0"]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, text=True)
            try:
                while not self.stop_event.is_set():
                    ready, _, _ = select.select([proc.stdout], [], [], 1.0)
                    if ready:
                        line = proc.stdout.readline()
                        if line:
                            self._process_ftp_line(line)
            finally:
                proc.terminate()
                proc.wait(timeout=3)
            return

        self.info(f"FTP brute-force: monitoring {log_path}")
        cmd = ["tail", "-F", "-n", "0", log_path]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True)
        try:
            while not self.stop_event.is_set():
                ready, _, _ = select.select([proc.stdout], [], [], 1.0)
                if ready:
                    line = proc.stdout.readline()
                    if line:
                        self._process_ftp_line(line)
        finally:
            proc.terminate()
            proc.wait(timeout=3)

    # -- lifecycle ---------------------------------------------------------

    def reset_state(self):
        self.failures_ssh.clear()
        self.failures_ftp.clear()
        self.blocked_ips.clear()
        self._safe_ip_notified.clear()
        for k in self.stats:
            self.stats[k] = 0

    def run(self):
        self._safe_ips = self._build_safe_ips()
        self.reset_state()
        ensure_chain(self.CHAIN)
        flush_chain(self.CHAIN)

        self._emit(f"[START] Brute-force detector v{self.VERSION} (SSH + FTP)")

        ftp_thread = threading.Thread(
            target=self._ftp_watcher, daemon=True, name='nids-bf-ftp')
        ftp_thread.start()

        try:
            self._ssh_watcher()
        finally:
            if self.stop_event:
                self.stop_event.set()
            ftp_thread.join(timeout=4)
            flush_chain(self.CHAIN)
            self._emit("[STOP] Brute-force detector stopped")


# ---------------------------------------------------------------------------
# Module-level compatibility
# ---------------------------------------------------------------------------
_callback = None
stats = {"ssh_lines": 0, "ftp_lines": 0, "blocks": 0}

def set_callback(fn):
    global _callback
    _callback = fn

def run_detector(cfg, stop_event=None):
    import threading as _t
    det = BruteForceDetector(cfg, stop_event or _t.Event(), _callback)
    det.run()
    stats.update(det.stats)

if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from config import load_config
    run_detector(load_config())
