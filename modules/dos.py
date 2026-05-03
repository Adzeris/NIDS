#!/usr/bin/env python3
"""
DoS / volumetric flood detector v2.0 — CUSUM change-point detection.

Detection strategies:
  Threshold + CUSUM: alert on direct packet-rate thresholds, and also track
  sustained upward drift with CUSUM after a short calibration phase.

      S_n = max(0, S_{n-1} + (x_n − μ₀ − k))
      Alarm when S_n > h

      μ₀ = learned baseline mean, k = slack (μ₀ × 0.5), h = decision threshold.

Research features:
  - Per-alert feature vectors (pps, cusum_value, baseline_mean, ...)
  - Confidence scoring
  - Detect-only mode
"""

import subprocess
import time
import re
from collections import defaultdict

from modules.detector_base import BaseDetector, cusum_step, rolling_stats
from modules.firewall import ensure_chain, flush_chain, block_ip, ts
from modules.host_network import get_interface_ip, collect_trusted_infrastructure_ips


class DoSDetector(BaseDetector):

    NAME = 'dos'
    VERSION = '2.0'
    CHAIN = 'NIDS_DOS'

    CALIBRATION_SAMPLES = 10  # samples before CUSUM activates

    def __init__(self, cfg, stop_event, log_callback=None):
        super().__init__(cfg, stop_event, log_callback)

        self.blocked_ips = set()
        self._safe_ips = set()
        self._safe_ip_notified = set()

        # CUSUM state per source
        self._cusum_s = defaultdict(float)
        self._rate_history = defaultdict(list)  # per-source sample history

        # Global calibration (aggregate)
        self._global_samples = []
        self._baseline_mean = None

        self.stats = {
            'samples': 0,
            'icmp_total': 0,
            'syn_total': 0,
            'sampled_total': 0,
            'blocks': 0,
        }

    def _build_safe_ips(self):
        return collect_trusted_infrastructure_ips(self.cfg, self.cfg['interface'])

    @staticmethod
    def _count_flood_packets_by_source(iface, monitored_ip=None):
        """Sample one second of ICMP echo and TCP SYN traffic by source IP."""
        cmd = ["sudo", "timeout", "1", "tcpdump", "-n", "-i", iface, "icmp or tcp"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        counts = defaultdict(int)
        breakdown = defaultdict(lambda: {'icmp_echo': 0, 'tcp_syn': 0})
        for line in proc.stdout.splitlines():
            m = re.search(
                r'IP\s+(\d+\.\d+\.\d+\.\d+)(?:\.\d+)?\s+>\s+'
                r'(\d+\.\d+\.\d+\.\d+)(?:\.\d+)?:', line)
            if not m:
                continue
            src_ip = m.group(1)
            dst_ip = m.group(2)
            if monitored_ip and dst_ip != monitored_ip:
                continue

            if 'ICMP echo request' in line:
                counts[src_ip] += 1
                breakdown[src_ip]['icmp_echo'] += 1
                continue

            # Count SYN-only packets so TCP SYN floods are visible to DoS logic.
            flags_m = re.search(r'Flags\s+\[([^\]]+)\]', line)
            if not flags_m:
                continue
            flags = flags_m.group(1)
            if 'S' in flags and '.' not in flags:
                counts[src_ip] += 1
                breakdown[src_ip]['tcp_syn'] += 1

        return counts, breakdown

    # -- feature extraction ------------------------------------------------

    def _features(self, src_ip, pps, cusum_val, *, icmp_pps=0, syn_pps=0):
        hist = self._rate_history.get(src_ip, [])
        mean_r, std_r = rolling_stats(hist) if len(hist) >= 2 else (0.0, 0.0)

        return {
            'source_pps': pps,
            'icmp_echo_pps': icmp_pps,
            'tcp_syn_pps': syn_pps,
            'cusum_value': round(cusum_val, 4),
            'baseline_mean': round(self._baseline_mean or 0.0, 4),
            'rate_history_len': len(hist),
            'rate_mean': round(mean_r, 2),
            'rate_std': round(std_r, 2),
            'calibrating': self._baseline_mean is None,
        }

    def _confidence(self, feat, threshold):
        c_threshold = min(1.0, feat['source_pps'] / max(threshold, 1))

        if self._baseline_mean is not None and self._baseline_mean > 0:
            h = self._baseline_mean * 5
            c_cusum = min(1.0, feat['cusum_value'] / max(h, 1.0))
            conf = 0.50 * c_threshold + 0.50 * c_cusum
        else:
            conf = c_threshold
        return round(min(1.0, conf), 4)

    # -- main loop ---------------------------------------------------------

    def reset_state(self):
        self.blocked_ips.clear()
        self._safe_ip_notified.clear()
        self._cusum_s.clear()
        self._rate_history.clear()
        self._global_samples.clear()
        self._baseline_mean = None
        for k in self.stats:
            self.stats[k] = 0

    def run(self):
        iface = self.cfg['interface']
        threshold = self.cfg['dos']['threshold_pps']
        syn_threshold = int(self.cfg['dos'].get(
            'syn_threshold_pps', max(80, threshold // 3)))
        # Keep CUSUM from reacting to low-rate normal TCP handshakes.
        min_pps_for_cusum = max(20, int(threshold * 0.1))
        monitored_ip = self.cfg.get('spoof', {}).get('host_ip', '').strip()
        if not monitored_ip:
            try:
                monitored_ip = get_interface_ip(iface)
            except OSError:
                monitored_ip = None
        self._safe_ips = self._build_safe_ips()
        self.reset_state()

        ensure_chain(self.CHAIN)
        flush_chain(self.CHAIN)
        self._emit(f"[START] DoS detector v{self.VERSION}")
        self.info(
            f"DoS monitor target={monitored_ip or 'any'} "
            f"icmp_threshold={threshold} syn_threshold={syn_threshold}"
        )

        try:
            while not self.stop_event.is_set():
                counts, breakdown = self._count_flood_packets_by_source(
                    iface, monitored_ip)
                self.stats['samples'] += 1
                total = sum(counts.values())
                icmp_total = sum(v['icmp_echo'] for v in breakdown.values())
                syn_total = sum(v['tcp_syn'] for v in breakdown.values())
                self.stats['icmp_total'] += icmp_total
                self.stats['syn_total'] += syn_total
                self.stats['sampled_total'] += total

                # Global calibration for CUSUM baseline
                self._global_samples.append(total)
                if (self._baseline_mean is None
                        and len(self._global_samples) >= self.CALIBRATION_SAMPLES):
                    # Learn background traffic rate from opening samples before
                    # change-point logic is enabled.
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
                    proto_counts = breakdown.get(src_ip, {})
                    icmp_pps = proto_counts.get('icmp_echo', 0)
                    syn_pps = proto_counts.get('tcp_syn', 0)
                    feat = self._features(
                        src_ip, pps, cusum_val,
                        icmp_pps=icmp_pps, syn_pps=syn_pps,
                    )
                    conf = self._confidence(feat, threshold)
                    feat['confidence'] = conf

                    # Decision
                    triggered = (
                        pps > threshold
                        or icmp_pps > threshold
                        or syn_pps > syn_threshold
                    )
                    if (not triggered
                            and self._baseline_mean is not None):
                        # CUSUM complements static thresholds by accumulating
                        # evidence of sustained positive drift.
                        h = self._baseline_mean * 5
                        triggered = pps >= min_pps_for_cusum and cusum_val > h

                    if triggered:
                        msg = (f"DoS flood from {src_ip} — {pps} pps"
                               f"  [ICMP={icmp_pps}, SYN={syn_pps}]")
                        self.alert(message=msg, source_ip=src_ip,
                                   confidence=conf, features=feat)

                        if src_ip in self._safe_ips:
                            if src_ip not in self._safe_ip_notified:
                                self.warn(f"{src_ip} is whitelisted (gateway) — logged once, will not repeat")
                                self._safe_ip_notified.add(src_ip)
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
stats = {"samples": 0, "icmp_total": 0, "syn_total": 0, "sampled_total": 0, "blocks": 0}

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
