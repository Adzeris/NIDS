#!/usr/bin/env python3
"""
Port scan detector v2.0 — entropy-augmented multi-strategy detection.

Detection strategies:
  Threshold + entropy scoring: alert when fixed thresholds are exceeded, or
  when lower-volume traffic looks strongly scan-like based on destination-port
  entropy and confidence scoring.

Scan types: TCP SYN, Stealth (Xmas/Null/FIN/ACK), UDP probes — each with
fast and slow detection windows.

Research features:
  - Per-alert feature vectors (unique_ports, probe_count, port_entropy, ...)
  - Confidence scoring
  - Detect-only mode
"""

from scapy.all import sniff, IP, TCP, UDP, Ether
import time
import math
import ipaddress
from collections import defaultdict, deque, Counter

from modules.detector_base import BaseDetector, shannon_entropy
from modules.firewall import ensure_chain, flush_chain, block_ip
from modules.host_network import get_interface_ip, collect_trusted_infrastructure_ips
from modules.detected_mac_persist import persist as persist_detected_mac


class PortScanDetector(BaseDetector):

    NAME = 'portscan'
    VERSION = '2.0'
    CHAIN = 'NIDS_PORTSCAN'

    _STEALTH_FLAGS = frozenset({"", "F", "FPU", "A"})
    _STEALTH_LABEL = {"": "Null", "F": "FIN", "FPU": "Xmas", "A": "ACK"}

    def __init__(self, cfg, stop_event, log_callback=None):
        super().__init__(cfg, stop_event, log_callback)

        self._defense_ip = None
        self._safe_ips = set()
        self._start_time = None

        self.syn_ports = defaultdict(deque)
        self.syn_times = defaultdict(deque)
        self.slow_syn_ports = defaultdict(deque)
        self.slow_syn_times = defaultdict(deque)

        self.stealth_ports = defaultdict(deque)
        self.stealth_times = defaultdict(deque)
        self.slow_stealth_ports = defaultdict(deque)
        self.slow_stealth_times = defaultdict(deque)

        self.udp_ports = defaultdict(deque)
        self.udp_times = defaultdict(deque)

        self.blocked_ips = set()
        # IPs for which we have already logged one "whitelisted — alert only" notice
        self._safe_ip_notified = set()
        self.stats = {
            'syn_packets': 0, 'stealth_packets': 0,
            'udp_packets': 0, 'blocks': 0,
        }

    # -- helpers -----------------------------------------------------------

    def _build_safe_ips(self):
        return collect_trusted_infrastructure_ips(self.cfg, self.cfg['interface'])

    @staticmethod
    def _is_local_source(ip_text):
        try:
            ip_obj = ipaddress.ip_address(ip_text)
        except ValueError:
            return False
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local

    @staticmethod
    def _prune(ports_dq, times_dq, src, now, window):
        while ports_dq[src] and (now - ports_dq[src][0][0]) > window:
            ports_dq[src].popleft()
        while times_dq[src] and (now - times_dq[src][0]) > window:
            times_dq[src].popleft()

    # -- feature extraction ------------------------------------------------

    def _features(self, src, ports_dq, times_dq, window, scan_type):
        port_counter = Counter(p for _, p in ports_dq[src])
        unique = set(port_counter.keys())
        n_unique = len(unique)
        n_probes = len(times_dq[src])

        # Entropy captures how evenly probes are spread across destination ports.
        # Scans tend to distribute attention broadly, while normal traffic often
        # clusters around a few stable services.
        entropy = shannon_entropy(port_counter) if n_unique > 1 else 0.0
        max_ent = math.log2(n_unique) if n_unique > 1 else 0.0
        ent_ratio = entropy / max_ent if max_ent > 0 else 0.0
        probe_rate = n_probes / window if window > 0 else 0.0
        port_range = (max(unique) - min(unique)) if n_unique > 0 else 0

        return {
            'unique_ports': n_unique,
            'probe_count': n_probes,
            'window_sec': window,
            'port_entropy': round(entropy, 4),
            'max_entropy': round(max_ent, 4),
            'entropy_ratio': round(ent_ratio, 4),
            'probe_rate': round(probe_rate, 2),
            'port_range': port_range,
            'scan_type': scan_type,
        }

    def _confidence(self, feat, port_thr, probe_thr):
        c_ports = min(1.0, feat['unique_ports'] / max(port_thr, 1))
        c_probes = min(1.0, feat['probe_count'] / max(probe_thr, 1))

        if feat['unique_ports'] > 2:
            # Entropy is treated as a third signal rather than a replacement
            # for the core threshold checks.
            c_ent = min(1.0, feat['port_entropy'] / max(1.5, 0.01))
            conf = 0.35 * c_ports + 0.35 * c_probes + 0.30 * c_ent
        else:
            conf = 0.5 * c_ports + 0.5 * c_probes
        return round(min(1.0, conf), 4)

    # -- scan evaluation ---------------------------------------------------

    def _check_scan(self, src, pkt, ports_dq, times_dq,
                    window, port_thr, probe_thr, label):
        feat = self._features(src, ports_dq, times_dq, window, label)
        conf = self._confidence(feat, port_thr, probe_thr)
        feat['confidence'] = conf

        triggered = (feat['unique_ports'] >= port_thr
                     and feat['probe_count'] >= probe_thr)
        if not triggered:
            # Entropy path catches low-and-slow patterns that stay just below
            # hard threshold counts.
            triggered = (conf >= 0.70
                         and feat['port_entropy'] > 1.0
                         and feat['unique_ports'] >= max(port_thr // 2, 3))

        if triggered:
            self._do_alert_block(src, pkt, feat, conf, window, label)
            return True
        return False

    def _do_alert_block(self, src, pkt, feat, conf, window, label):
        src_mac = pkt[Ether].src.upper() if pkt.haslayer(Ether) else 'unknown'
        if src in self._safe_ips:
            # Silently drop repeat triggers from whitelisted IPs; we only alert once.
            if src in self._safe_ip_notified:
                self._clear_tracking(src)
                return

        msg = (f"{label} scan from {src} / {src_mac} "
               f"({feat['unique_ports']} ports, {feat['probe_count']} probes "
               f"in {window}s, entropy={feat['port_entropy']:.2f})")

        self.alert(message=msg, source_ip=src, source_mac=src_mac,
                   confidence=conf, features=feat)

        if src_mac != 'unknown':
            persist_detected_mac(src_mac, src, lambda m: self._emit(m))

        if src in self._safe_ips:
            self.warn(f"{src} is whitelisted (gateway) — logged once, will not repeat")
            self._safe_ip_notified.add(src)
        else:
            blocked = self.block(
                target=src, reason=f"{label} scan",
                source_ip=src, source_mac=src_mac,
                confidence=conf, features=feat,
                do_block_fn=lambda: block_ip(self.CHAIN, src),
            )
            if blocked:
                self.blocked_ips.add(src)
                self.stats['blocks'] += 1

        self._clear_tracking(src)

    def _clear_tracking(self, src):
        for dq in (self.syn_ports, self.syn_times,
                   self.slow_syn_ports, self.slow_syn_times,
                   self.stealth_ports, self.stealth_times,
                   self.slow_stealth_ports, self.slow_stealth_times,
                   self.udp_ports, self.udp_times):
            dq[src].clear()

    # -- packet handlers ---------------------------------------------------

    def _on_packet(self, pkt):
        now = time.time()
        if now - self._start_time < 1:
            return
        if IP not in pkt:
            return
        src, dst = pkt[IP].src, pkt[IP].dst
        ps_cfg = self.cfg.get('portscan', {})
        if ps_cfg.get('local_sources_only', True) and not self._is_local_source(src):
            # Ignore internet background noise (public cloud/CDN sources) when the
            # detector is intended for LAN attacker demonstrations.
            return
        if src in self.blocked_ips:
            return

        if TCP in pkt:
            self._handle_tcp(pkt, src, dst, now)
        elif UDP in pkt:
            self._handle_udp(pkt, src, dst, now)

    def _handle_tcp(self, pkt, src, dst, now):
        if dst != self._defense_ip or src == self._defense_ip:
            return
        flags = str(pkt[TCP].flags)
        dport = int(pkt[TCP].dport)

        if flags == 'S':
            self._handle_syn(pkt, src, dport, now)
        elif flags in self._STEALTH_FLAGS:
            self._handle_stealth(pkt, src, dport, now, flags)

    def _handle_syn(self, pkt, src, dport, now):
        ps = self.cfg['portscan']
        self.stats['syn_packets'] += 1

        # fast window
        self.syn_ports[src].append((now, dport))
        self.syn_times[src].append(now)
        self._prune(self.syn_ports, self.syn_times, src, now, ps['window_sec'])

        if self._check_scan(src, pkt, self.syn_ports, self.syn_times,
                            ps['window_sec'], ps['port_threshold'],
                            ps['syn_threshold'], 'TCP SYN'):
            return

        # slow window
        self.slow_syn_ports[src].append((now, dport))
        self.slow_syn_times[src].append(now)
        slow_w = ps.get('slow_window_sec', 120)
        self._prune(self.slow_syn_ports, self.slow_syn_times, src, now, slow_w)

        self._check_scan(src, pkt, self.slow_syn_ports, self.slow_syn_times,
                         slow_w, ps.get('slow_port_threshold', ps['port_threshold']),
                         ps.get('slow_syn_threshold', ps['syn_threshold']),
                         'Slow TCP SYN')

    def _handle_stealth(self, pkt, src, dport, now, flags):
        ps = self.cfg['portscan']
        scan_name = self._STEALTH_LABEL.get(flags, 'Stealth')
        self.stats['stealth_packets'] += 1

        self.stealth_ports[src].append((now, dport))
        self.stealth_times[src].append(now)
        self._prune(self.stealth_ports, self.stealth_times,
                    src, now, ps['window_sec'])

        if self._check_scan(src, pkt, self.stealth_ports, self.stealth_times,
                            ps['window_sec'], ps['port_threshold'],
                            ps['syn_threshold'], f'Stealth/{scan_name}'):
            return

        self.slow_stealth_ports[src].append((now, dport))
        self.slow_stealth_times[src].append(now)
        slow_w = ps.get('slow_window_sec', 120)
        self._prune(self.slow_stealth_ports, self.slow_stealth_times,
                    src, now, slow_w)

        self._check_scan(src, pkt, self.slow_stealth_ports,
                         self.slow_stealth_times, slow_w,
                         ps.get('slow_port_threshold', ps['port_threshold']),
                         ps.get('slow_syn_threshold', ps['syn_threshold']),
                         f'Slow Stealth/{scan_name}')

    def _handle_udp(self, pkt, src, dst, now):
        if dst != self._defense_ip or src == self._defense_ip:
            return
        ps = self.cfg['portscan']
        dport = int(pkt[UDP].dport)
        self.stats['udp_packets'] += 1

        self.udp_ports[src].append((now, dport))
        self.udp_times[src].append(now)
        udp_w = ps.get('udp_window_sec', 10)
        self._prune(self.udp_ports, self.udp_times, src, now, udp_w)

        self._check_scan(src, pkt, self.udp_ports, self.udp_times,
                         udp_w, ps.get('udp_port_threshold', 8),
                         ps.get('udp_probe_threshold', 12), 'UDP')

    # -- lifecycle ---------------------------------------------------------

    def reset_state(self):
        for dq in (self.syn_ports, self.syn_times,
                   self.slow_syn_ports, self.slow_syn_times,
                   self.stealth_ports, self.stealth_times,
                   self.slow_stealth_ports, self.slow_stealth_times,
                   self.udp_ports, self.udp_times):
            dq.clear()
        self.blocked_ips.clear()
        self._safe_ip_notified.clear()
        for k in self.stats:
            self.stats[k] = 0

    def run(self):
        iface = self.cfg['interface']
        self._defense_ip = get_interface_ip(iface)
        self._safe_ips = self._build_safe_ips()
        self._start_time = time.time()

        self.reset_state()
        ensure_chain(self.CHAIN)
        flush_chain(self.CHAIN)

        ps = self.cfg['portscan']
        from modules.firewall import run as fw_run
        fw_run(["sudo", "iptables", "-A", self.CHAIN, "-p", "tcp", "--syn",
                "-m", "recent", "--name", "nids_ps", "--set"])
        fw_run(["sudo", "iptables", "-A", self.CHAIN, "-p", "tcp", "--syn",
                "-m", "recent", "--name", "nids_ps", "--rcheck",
                "--seconds", str(ps['window_sec']),
                "--hitcount", str(ps['syn_threshold']), "-j", "DROP"])

        self._emit(f"[START] Port-scan detector v{self.VERSION} on {iface} "
                   f"(IP: {self._defense_ip})")

        try:
            while not self.stop_event.is_set():
                sniff(
                    iface=iface,
                    prn=self._on_packet,
                    store=False,
                    filter="tcp or udp",
                    timeout=2,
                    stop_filter=lambda _: self.stop_event.is_set(),
                )
        finally:
            flush_chain(self.CHAIN)
            self._emit("[STOP] Port-scan detector stopped")


# ---------------------------------------------------------------------------
# Module-level compatibility (standalone use + legacy engine fallback)
# ---------------------------------------------------------------------------
_callback = None
stats = {"syn_packets": 0, "stealth_packets": 0, "udp_packets": 0, "blocks": 0}

def set_callback(fn):
    global _callback
    _callback = fn

def run_detector(cfg, stop_event=None):
    import threading
    det = PortScanDetector(cfg, stop_event or threading.Event(), _callback)
    det.run()
    stats.update(det.stats)

if __name__ == "__main__":
    import sys, os, threading
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from config import load_config
    run_detector(load_config())
