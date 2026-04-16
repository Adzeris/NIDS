#!/usr/bin/env python3
"""
MAC address filter v2.0 — policy enforcement with research instrumentation.

This module is primarily a policy-enforcement layer (whitelist/blacklist)
rather than a detection algorithm, but it participates in the research
framework by emitting structured events with per-MAC feature context.

Research features:
  - Per-action feature vectors (mac, ip, mode, list membership)
  - Confidence scoring (policy match = 1.0)
  - Detect-only mode
"""

from scapy.all import sniff, Ether, IP
import time

from modules.base import BaseDetector
from modules.firewall import ensure_chain, flush_chain, block_mac, unblock_mac
from modules.netutil import get_interface_ip, get_default_gateway
from modules.detected_mac_persist import persist as persist_detected_mac


class MACFilterDetector(BaseDetector):

    NAME = 'macfilter'
    VERSION = '2.0'
    CHAIN = 'NIDS_MACFILTER'

    def __init__(self, cfg, stop_event, log_callback=None):
        super().__init__(cfg, stop_event, log_callback)

        self._defense_ip = None
        self._safe_ips = set()
        self._blocked_macs = set()
        self._alerted_macs = set()

        self.stats = {'frames': 0, 'blocks': 0}

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

    def _on_packet(self, pkt):
        if not pkt.haslayer(Ether):
            return

        self.stats['frames'] += 1
        src_mac = pkt[Ether].src.upper()
        src_ip = pkt[IP].src if pkt.haslayer(IP) else 'N/A'

        if src_ip == self._defense_ip or src_ip in self._safe_ips:
            return

        mc = self.cfg['macfilter']
        mode = mc['mode']
        allowed = {m.upper() for m in mc['allowed_macs']}
        deny = {m.upper() for m in mc['blocked_macs']}

        should_block = False
        if mode == 'whitelist':
            if allowed and src_mac not in allowed:
                should_block = True
        elif mode == 'blacklist':
            if src_mac in deny:
                should_block = True

        if should_block and src_mac not in self._blocked_macs:
            features = {
                'mac': src_mac,
                'ip': src_ip,
                'filter_mode': mode,
                'in_allowed': src_mac in allowed,
                'in_blocked': src_mac in deny,
            }
            msg = f"Unauthorised MAC {src_mac} ({src_ip})"
            self.alert(message=msg, source_ip=src_ip, source_mac=src_mac,
                       confidence=1.0, features=features)

            blocked = self.block(
                target=src_mac, reason=f"MAC policy ({mode})",
                source_ip=src_ip, source_mac=src_mac,
                confidence=1.0, features=features,
                do_block_fn=lambda: block_mac(self.CHAIN, src_mac),
            )
            if blocked:
                self._blocked_macs.add(src_mac)
                self.stats['blocks'] += 1
            persist_detected_mac(src_mac, src_ip, lambda m: self._emit(m))

        if not should_block and src_mac in self._blocked_macs:
            unblock_mac(self.CHAIN, src_mac)
            self._blocked_macs.discard(src_mac)
            self._emit(f"[UNBLOCK] MAC {src_mac} ({src_ip}) removed from block list")

    # -- lifecycle ---------------------------------------------------------

    def reset_state(self):
        self._blocked_macs.clear()
        self._alerted_macs.clear()
        for k in self.stats:
            self.stats[k] = 0

    def run(self):
        cfg = self.cfg
        iface = cfg['interface']

        self._defense_ip = get_interface_ip(iface)
        self._safe_ips = self._build_safe_ips()
        self.reset_state()

        ensure_chain(self.CHAIN)
        flush_chain(self.CHAIN)

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


# ---------------------------------------------------------------------------
# Module-level compatibility
# ---------------------------------------------------------------------------
_callback = None
stats = {"frames": 0, "blocks": 0}

def set_callback(fn):
    global _callback
    _callback = fn

def run_detector(cfg, stop_event=None):
    import threading
    det = MACFilterDetector(cfg, stop_event or threading.Event(), _callback)
    det.run()
    stats.update(det.stats)

if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from config import load_config
    run_detector(load_config())
