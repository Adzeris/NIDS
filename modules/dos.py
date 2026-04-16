#!/usr/bin/env python3
"""
DoS / volumetric flood detector v2.0 — CUSUM change-point detection.

Detection strategies:
  Baseline (threshold):  alert when ICMP packets-per-second from a single
                         source exceed a fixed threshold in a 1-second sample.
  Improved (CUSUM):      Cumulative Sum change-point algorithm.  Learns a
      baseline traffic rate during an initial calibration window, then tracks
      cumulative deviation.  Detects both sudden spikes AND gradual ramp-ups
      that stay below the static threshold until the flood is fully underway.

      S_n = max(0, S_{n-1} + (x_n − μ₀ − k))
      Alarm when S_n > h

      μ₀ = learned baseline mean, k = slack (μ₀ × 0.5), h = decision threshold.

Research features:
  - Per-alert feature vectors (pps, cusum_value, baseline_mean, ...)
  - Confidence scoring
  - Baseline / improved mode switching
  - Detect-only mode
"""

import subprocess
import time
import re
from collections import defaultdict

from modules.base import BaseDetector, cusum_step, rolling_stats
from modules.firewall import ensure_chain, flush_chain, block_ip, ts
from modules.netutil import get_default_gateway


class DoSDetector(BaseDetector):

    NAME = 'dos'
    VERSION = '2.0'
    CHAIN = 'NIDS_DOS'

    CALIBRATION_SAMPLES = 10  # samples before CUSUM activates

    def __init__(self, cfg, stop_event, log_callback=None):
        super().__init__(cfg, stop_event, log_callback)

        self.blocked_ips = set()
        self._safe_ips = set()

        # CUSUM state per source
        self._cusum_s = defaultdict(float)
        self._rate_history = defaultdict(list)  # per-source sample history

        # Global calibration (aggregate)
        self._global_samples = []
        self._baseline_mean = None

        self.stats = {'samples': 0, 'icmp_total': 0, 'blocks': 0}

    def _build_safe_ips(self):
        cfg = self.cfg
        iface = cfg['interface']
        safe = {'0.0.0.0', '255.255.255.255'}
        if cfg.get('network_mode', 'nat') == 'bridged':
            gw = get_default_gateway(iface)
            if gw and cfg.get('spoof', {}).get('gateway_auto_whitelist', True):
                safe.add(gw)
            host = cfg.get('spoof', {}).get('host_ip', '').strip()
            if cfg.get('spoof', {}).get('whitelist_host') and host:
                safe.add(host)
        for ip_str in cfg.get('spoof', {}).get('whitelist_ips', []):
            safe.add(ip_str.strip())
        return safe

    @staticmethod
    def _count_icmp_by_source(iface):
        cmd = ["sudo", "timeout", "1", "tcpdump", "-n", "-i", iface, "icmp"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        counts = defaultdict(int)
        for line in proc.stdout.splitlines():
            m = re.search(
                r'IP\s+(\d+\.\d+\.\d+\.\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+):', line)
            if not m:
                continue
            if 'ICMP echo request' not in line:
                continue
            counts[m.group(1)] += 1
        return counts

    # -- feature extraction ------------------------------------------------

    def _features(self, src_ip, pps, cusum_val):
        hist = self._rate_history.get(src_ip, [])
        mean_r, std_r = rolling_stats(hist) if len(hist) >= 2 else (0.0, 0.0)

        return {
            'source_pps': pps,
            'cusum_value': round(cusum_val, 4),
            'baseline_mean': round(self._baseline_mean or 0.0, 4),
            'rate_history_len': len(hist),
            'rate_mean': round(mean_r, 2),
            'rate_std': round(std_r, 2),
            'calibrating': self._baseline_mean is None,
        }

    def _confidence(self, feat, threshold):
        c_threshold = min(1.0, feat['source_pps'] / max(threshold, 1))

        if (self.method == 'improved'
                and self._baseline_mean is not None
                and self._baseline_mean > 0):
            h = self._baseline_mean * 5
            c_cusum = min(1.0, feat['cusum_value'] / max(h, 1.0))
            conf = 0.50 * c_threshold + 0.50 * c_cusum
        else:
            conf = c_threshold
        return round(min(1.0, conf), 4)

    # -- main loop ---------------------------------------------------------

    def reset_state(self):
        self.blocked_ips.clear()
        self._cusum_s.clear()
        self._rate_history.clear()
        self._global_samples.clear()
        self._baseline_mean = None
        for k in self.stats:
            self.stats[k] = 0

    def run(self):
        iface = self.cfg['interface']
        threshold = self.cfg['dos']['threshold_pps']
        self._safe_ips = self._build_safe_ips()
        self.reset_state()

        ensure_chain(self.CHAIN)
        flush_chain(self.CHAIN)
        self._emit(f"[START] DoS detector v{self.VERSION}")

        try:
            while not self.stop_event.is_set():
                counts = self._count_icmp_by_source(iface)
                self.stats['samples'] += 1
                total = sum(counts.values())
                self.stats['icmp_total'] += total

                # Global calibration for CUSUM baseline
                self._global_samples.append(total)
                if (self._baseline_mean is None
                        and len(self._global_samples) >= self.CALIBRATION_SAMPLES):
                    mean, _ = rolling_stats(self._global_samples)
                    self._baseline_mean = max(mean, 1.0)

                for src_ip, pps in counts.items():
                    if src_ip in self.blocked_ips:
                        continue

                    self._rate_history[src_ip].append(pps)

                    # CUSUM update
                    if self._baseline_mean is not None:
                        slack = self._baseline_mean * 0.5
                        self._cusum_s[src_ip] = cusum_step(
                            self._cusum_s[src_ip], pps,
                            self._baseline_mean, slack)

                    cusum_val = self._cusum_s.get(src_ip, 0.0)
                    feat = self._features(src_ip, pps, cusum_val)
                    conf = self._confidence(feat, threshold)
                    feat['confidence'] = conf

                    # Decision
                    if self.method == 'baseline':
                        triggered = pps > threshold
                    else:
                        triggered = pps > threshold
                        if (not triggered
                                and self._baseline_mean is not None):
                            h = self._baseline_mean * 5
                            triggered = cusum_val > h

                    if triggered:
                        msg = (f"DoS flood from {src_ip}: {pps} pps"
                               f" (CUSUM={cusum_val:.1f})")
                        self.alert(message=msg, source_ip=src_ip,
                                   confidence=conf, features=feat)

                        if src_ip in self._safe_ips:
                            self.warn(f"{src_ip} is gateway/whitelisted — alert only")
                        else:
                            blocked = self.block(
                                target=src_ip, reason="DoS flood",
                                source_ip=src_ip, confidence=conf,
                                features=feat,
                                do_block_fn=lambda ip=src_ip: block_ip(
                                    self.CHAIN, ip),
                            )
                            if blocked:
                                self.blocked_ips.add(src_ip)
                                self.stats['blocks'] += 1

                        self._cusum_s[src_ip] = 0.0
        finally:
            flush_chain(self.CHAIN)
            self._emit("[STOP] DoS detector stopped")


# ---------------------------------------------------------------------------
# Module-level compatibility
# ---------------------------------------------------------------------------
_callback = None
stats = {"samples": 0, "icmp_total": 0, "blocks": 0}

def set_callback(fn):
    global _callback
    _callback = fn

def run_detector(cfg, stop_event=None):
    import threading
    det = DoSDetector(cfg, stop_event or threading.Event(), _callback)
    det.run()
    stats.update(det.stats)

if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from config import load_config
    run_detector(load_config())
