#!/usr/bin/env python3
"""
MAC address filter v2.0 — explicit blocklist policy enforcement.

This module is a policy layer, not a traffic anomaly detector.
It checks source MAC addresses against the configured blocked list and
emits structured events for alert/block history.
"""

from scapy.all import sniff, Ether, IP
import time

from modules.base import BaseDetector
from modules.firewall import ensure_chain, flush_chain, block_mac, unblock_mac
from modules.netutil import (
    get_interface_ip,
    collect_trusted_infrastructure_ips,
    get_default_gateway,
    get_default_gateway_mac,
)
from modules.detected_mac_persist import persist as persist_detected_mac


class MACFilterDetector(BaseDetector):

    NAME = 'macfilter'
    VERSION = '2.0'
    CHAIN = 'NIDS_MACFILTER'

    def __init__(self, cfg, stop_event, log_callback=None):
        super().__init__(cfg, stop_event, log_callback)

        self._defense_ip = None
        self._safe_ips = set()
        self._iface = None
        self._gateway_ip = None
        self._gateway_mac = None
        self._blocked_macs = set()
        self._alerted_macs = set()

        self.stats = {'frames': 0, 'blocks': 0}

    def _build_safe_ips(self):
        return collect_trusted_infrastructure_ips(self.cfg, self.cfg['interface'])

    def _on_packet(self, pkt):
        if not pkt.haslayer(Ether):
            return

        self.stats['frames'] += 1
        src_mac = pkt[Ether].src.upper()
        src_ip = pkt[IP].src if pkt.haslayer(IP) else 'N/A'

        if src_ip == self._defense_ip or src_ip in self._safe_ips:
            # Learn/refresh gateway MAC from direct gateway traffic.
            if self._gateway_ip and src_ip == self._gateway_ip:
                self._gateway_mac = src_mac
            return
        # Inbound routed traffic: L3 source may be remote, while L2 source is often
        # the default gateway MAC. Do not flag the gateway MAC as an attacker.
        if self._gateway_mac is None and self._gateway_ip and self._iface:
            self._gateway_mac = get_default_gateway_mac(self._iface, self._gateway_ip)
        if self._gateway_mac and src_mac == self._gateway_mac:
            return

        mc = self.cfg['macfilter']
        allowed = {m.upper() for m in mc.get('allowed_macs', [])}
        deny = {m.upper() for m in mc.get('blocked_macs', [])}

        # Enforcement is explicit blocked-list policy. Allowed list is used by
        # the GUI to organize reviewed devices, not to auto-block everything else.
        should_block = src_mac in deny

        if should_block and src_mac not in self._blocked_macs:
            features = {
                'mac': src_mac,
                'ip': src_ip,
                'policy': 'blocked_list',
                'in_allowed': src_mac in allowed,
                'in_blocked': src_mac in deny,
            }
            msg = f"MAC blocklist hit: {src_ip} / {src_mac}"
            self.alert(message=msg, source_ip=src_ip, source_mac=src_mac,
                       confidence=1.0, features=features)

            blocked = self.block(
                target=src_mac, reason="MAC policy (blocked_list)",
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
            self._emit(f"[UNBLOCK] {src_ip} / {src_mac} removed from block list")

    # -- lifecycle ---------------------------------------------------------

    def reset_state(self):
        self._blocked_macs.clear()
        self._alerted_macs.clear()
        for k in self.stats:
            self.stats[k] = 0

    def run(self):
        cfg = self.cfg
        iface = cfg['interface']
        self._iface = iface

        self._defense_ip = get_interface_ip(iface)
        self._safe_ips = self._build_safe_ips()
        sp = self.cfg.get('spoof', {})
        self._gateway_ip = None
        self._gateway_mac = None
        if sp.get('whitelist_default_gateway', True):
            self._gateway_ip = get_default_gateway(iface)
            self._gateway_mac = get_default_gateway_mac(iface, self._gateway_ip)
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
