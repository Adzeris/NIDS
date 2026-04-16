#!/usr/bin/env python3
"""
IP / ARP spoof detector v2.0 — multi-signal statistical detection.

Detection signals:
  1. ARP cache poisoning — alerts when an IP's MAC binding changes
     (classic MitM indicator).
  2. Bogon source filtering — flags packets from reserved/invalid ranges.
  3. TTL anomaly detection:
     Baseline (mode-deviation): alert when observed TTL deviates from the
         most-common initial TTL by more than a fixed threshold.
     Improved (Z-score):  track per-source TTL distribution (rolling mean
         and standard deviation).  Alert when the Z-score of the current
         observation exceeds a configurable threshold.  More statistically
         principled — distinguishes true anomalies from normal route-change
         variation.

Multi-signal confidence aggregation combines ARP, TTL, and bogon signals
into a single confidence score per source.

Research features:
  - Per-alert feature vectors (z_score, ttl_mean, ttl_std, arp_changes, ...)
  - Confidence scoring with per-signal weights
  - Baseline / improved mode switching
  - Detect-only mode
"""

from scapy.all import sniff, ARP, IP, Ether, srp
import time
import ipaddress
from collections import defaultdict, deque, Counter

from modules.base import BaseDetector, z_score, rolling_stats
from modules.firewall import ensure_chain, flush_chain, block_ip, block_mac
from modules.netutil import get_interface_ip, get_local_network, get_default_gateway
from modules import arpnft
from modules.detected_mac_persist import persist as persist_detected_mac


class SpoofDetector(BaseDetector):

    NAME = 'spoof'
    VERSION = '2.0'
    CHAIN = 'NIDS_SPOOF'

    STANDARD_TTLS = {32, 64, 128, 255}

    BOGON_NETS = [
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("192.0.0.0/24"),
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.18.0.0/15"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
        ipaddress.ip_network("240.0.0.0/4"),
    ]

    DHCP_SAFE = {
        ipaddress.ip_address("0.0.0.0"),
        ipaddress.ip_address("255.255.255.255"),
        ipaddress.ip_address("169.254.169.254"),
    }

    def __init__(self, cfg, stop_event, log_callback=None):
        super().__init__(cfg, stop_event, log_callback)

        self._defense_ip = None
        self._local_net = None
        self._gateway_ip = None
        self._safe_ips = set()
        self._start_time = None

        self.arp_table = {}
        self.arp_cooldowns = {}
        self.ttl_history = defaultdict(lambda: deque(maxlen=200))
        self.ttl_alert_cooldowns = {}
        self.ttl_alert_counts = defaultdict(int)
        self.blocked_ips = set()
        self.blocked_macs = set()

        self.stats = {'arp_packets': 0, 'ip_packets': 0, 'blocks': 0}

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _nearest_initial_ttl(ttl):
        for init in sorted(SpoofDetector.STANDARD_TTLS):
            if ttl <= init:
                return init
        return 255

    def _classify_bogon(self, addr):
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return None
        if ip in self.DHCP_SAFE or addr in self._safe_ips:
            return 'safe'
        if any(ip in net for net in self.BOGON_NETS):
            return 'block'
        return None

    # -- ARP detection -----------------------------------------------------

    def _handle_arp(self, pkt):
        sp_cfg = self.cfg['spoof']
        if not sp_cfg.get('arp_watch', True):
            return
        if pkt[ARP].op != 2:
            return

        src_ip = pkt[ARP].psrc
        src_mac = pkt[Ether].src.upper()
        cooldown = sp_cfg.get('arp_alert_cooldown', 30)

        if src_ip == self._defense_ip or src_mac in self.blocked_macs:
            return

        now = time.time()

        if src_ip in self.arp_table:
            old_mac = self.arp_table[src_ip]
            if old_mac != src_mac:
                ck = f"{src_ip}:{src_mac}"
                if ck not in self.arp_cooldowns or (now - self.arp_cooldowns[ck]) > cooldown:
                    features = {
                        'signal': 'arp_change',
                        'old_mac': old_mac,
                        'new_mac': src_mac,
                        'ip': src_ip,
                    }
                    msg = (f"ARP spoof detected: {src_ip} changed "
                           f"from {old_mac} → {src_mac} (possible MitM)")
                    self.alert(message=msg, source_ip=src_ip,
                               source_mac=src_mac, confidence=0.90,
                               features=features)

                    self.arp_cooldowns[ck] = now
                    block_mac(self.CHAIN, src_mac)
                    self.blocked_macs.add(src_mac)
                    if arpnft.arp_block_mac(src_mac, self.cfg['interface']):
                        self._emit(f"[BLOCK] Blocked MAC {src_mac} ({src_ip}) "
                                   f"(ARP poisoning — iptables + nftables)")
                    else:
                        self._emit(f"[BLOCK] Blocked MAC {src_mac} ({src_ip}) "
                                   f"(ARP poisoning — iptables only)")
                    persist_detected_mac(src_mac, src_ip, lambda m: self._emit(m))
                    self.stats['blocks'] += 1
                    return

        self.arp_table[src_ip] = src_mac

    # -- IP / TTL detection ------------------------------------------------

    def _handle_ip(self, pkt):
        src = pkt[IP].src
        now = time.time()

        if src == self._defense_ip or src in self.blocked_ips or src in self._safe_ips:
            return

        # Bogon check
        bogon = self._classify_bogon(src)
        if bogon == 'safe':
            return
        if bogon == 'block':
            feat = {'signal': 'bogon', 'source_ip': src}
            self.alert(message=f"Bogon source: {src}", source_ip=src,
                       confidence=0.95, features=feat)
            blocked = self.block(
                target=src, reason="bogon address", source_ip=src,
                confidence=0.95, features=feat,
                do_block_fn=lambda: block_ip(self.CHAIN, src),
            )
            if blocked:
                self.blocked_ips.add(src)
                self.stats['blocks'] += 1
            return

        # TTL analysis (local-only filter)
        sp_cfg = self.cfg['spoof']
        if sp_cfg.get('ttl_local_only', True) and self._local_net:
            try:
                if ipaddress.ip_address(src) not in self._local_net:
                    return
            except ValueError:
                return

        ttl = pkt[IP].ttl
        if ttl <= 1 or ttl == 255:
            return

        initial_ttl = self._nearest_initial_ttl(ttl)
        self.ttl_history[src].append(initial_ttl)
        history = self.ttl_history[src]

        min_samples = sp_cfg.get('ttl_min_samples', 10)
        if len(history) < min_samples:
            return

        max_alerts = sp_cfg.get('ttl_max_alerts_per_source', 3)
        if self.ttl_alert_counts[src] >= max_alerts:
            return

        cooldown = sp_cfg.get('ttl_alert_cooldown', 120)
        if src in self.ttl_alert_cooldowns and (now - self.ttl_alert_cooldowns[src]) <= cooldown:
            return

        # Baseline: mode-deviation check (original behaviour)
        # Improved: Z-score based check
        ttl_vals = list(history)
        mean_ttl, std_ttl = rolling_stats(ttl_vals)

        if self.method == 'baseline':
            counts = Counter(history)
            dominant_ttl, _ = counts.most_common(1)[0]
            deviation_thr = sp_cfg.get('ttl_deviation', 20)
            anomaly = (initial_ttl != dominant_ttl
                       and abs(ttl - dominant_ttl) > deviation_thr)
            z = abs(ttl - dominant_ttl) / max(deviation_thr, 1)
        else:
            z = z_score(initial_ttl, mean_ttl, std_ttl)
            z_threshold = sp_cfg.get('ttl_z_threshold', 2.5)
            anomaly = z > z_threshold

        if anomaly:
            self.ttl_alert_counts[src] += 1
            remaining = max_alerts - self.ttl_alert_counts[src]
            suppress = " (further alerts suppressed)" if remaining <= 0 else ""

            features = {
                'signal': 'ttl_anomaly',
                'observed_ttl': ttl,
                'initial_ttl': initial_ttl,
                'ttl_mean': round(mean_ttl, 2),
                'ttl_std': round(std_ttl, 2),
                'z_score': round(z, 4),
                'history_len': len(history),
                'method': self.method,
            }
            conf = min(1.0, z / 5.0) if z > 0 else 0.3

            msg = (f"TTL anomaly from {src}: got {ttl} (init {initial_ttl}), "
                   f"mean={mean_ttl:.1f}±{std_ttl:.1f}, z={z:.2f}"
                   f" — possible spoof{suppress}")
            self.alert(message=msg, source_ip=src, confidence=conf,
                       features=features)
            self.ttl_alert_cooldowns[src] = now

    # -- packet callback ---------------------------------------------------

    def _on_packet(self, pkt):
        now = time.time()
        if now - self._start_time < 1:
            return
        if pkt.haslayer(ARP):
            self.stats['arp_packets'] += 1
            self._handle_arp(pkt)
        if pkt.haslayer(IP):
            self.stats['ip_packets'] += 1
            self._handle_ip(pkt)

    # -- lifecycle ---------------------------------------------------------

    def reset_state(self):
        gw_ip = self._gateway_ip
        gw_mac = self.arp_table.get(gw_ip) if gw_ip else None
        self.arp_table.clear()
        if gw_ip and gw_mac:
            self.arp_table[gw_ip] = gw_mac
        self.arp_cooldowns.clear()
        self.ttl_history.clear()
        self.ttl_alert_cooldowns.clear()
        self.ttl_alert_counts.clear()
        self.blocked_ips.clear()
        self.blocked_macs.clear()
        for k in self.stats:
            self.stats[k] = 0

    def run(self):
        cfg = self.cfg
        iface = cfg['interface']
        self._defense_ip = get_interface_ip(iface)
        self._local_net = get_local_network(iface)
        self._gateway_ip = get_default_gateway(iface)
        self._start_time = time.time()

        self._safe_ips = {'0.0.0.0', '255.255.255.255'}
        if self._gateway_ip and cfg['spoof'].get('gateway_auto_whitelist', True):
            self._safe_ips.add(self._gateway_ip)
        host = cfg['spoof'].get('host_ip', '').strip()
        if cfg['spoof'].get('whitelist_host') and host:
            self._safe_ips.add(host)
        for ip_str in cfg['spoof'].get('whitelist_ips', []):
            self._safe_ips.add(ip_str.strip())

        self.reset_state()

        # Seed ARP table with gateway
        if self._gateway_ip:
            try:
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self._gateway_ip),
                             iface=iface, timeout=2, verbose=False)
                for _, rcv in ans:
                    gw_mac = rcv[Ether].src.upper()
                    self.arp_table[self._gateway_ip] = gw_mac
                    self.info(f"Gateway IP: {self._gateway_ip}")
                    break
            except Exception:
                pass

        ensure_chain(self.CHAIN)
        flush_chain(self.CHAIN)

        self._emit(f"[START] Spoof detector v{self.VERSION} on {iface} "
                   f"(IP: {self._defense_ip})")

        try:
            while not self.stop_event.is_set():
                sniff(
                    iface=iface,
                    prn=self._on_packet,
                    store=False,
                    timeout=2,
                    stop_filter=lambda _: self.stop_event.is_set(),
                )
        finally:
            flush_chain(self.CHAIN)
            arpnft.arp_flush_blocked()
            self._emit("[STOP] Spoof detector stopped")


# ---------------------------------------------------------------------------
# Module-level compatibility
# ---------------------------------------------------------------------------
_callback = None
stats = {"arp_packets": 0, "ip_packets": 0, "blocks": 0}

def set_callback(fn):
    global _callback
    _callback = fn

def run_detector(cfg, stop_event=None):
    import threading
    det = SpoofDetector(cfg, stop_event or threading.Event(), _callback)
    det.run()
    stats.update(det.stats)

if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from config import load_config
    run_detector(load_config())
