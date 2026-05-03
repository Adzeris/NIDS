#!/usr/bin/env python3
"""
Passive IoT device profiling for NIDS v5.0.

This detector is intentionally non-blocking. It builds a lightweight inventory
of observed LAN devices and flags scan-like fanout from a single device, which
is a common early signal of compromised IoT behavior.
"""

from collections import defaultdict, deque
import time

from scapy.all import ARP, Ether, IP, TCP, UDP, sniff

from modules.detector_base import BaseDetector
from modules.host_network import (
    collect_trusted_infrastructure_ips,
    get_default_gateway,
    get_default_gateway_mac,
    get_interface_ip,
)


class IoTProfileDetector(BaseDetector):
    NAME = 'iot_profile'
    VERSION = '0.1'
    CHAIN = 'NIDS_IOT_PROFILE'

    def __init__(self, cfg, stop_event, log_callback=None):
        super().__init__(cfg, stop_event, log_callback)
        self._devices = {}
        self._port_windows = defaultdict(deque)
        self._last_alert = {}
        self._iface = None
        self._defense_ip = None
        self._gateway_ip = None
        self._gateway_mac = None
        self._safe_ips = set()
        self.stats = {
            'packets': 0,
            'devices': 0,
            'new_devices': 0,
            'anomalies': 0,
        }

    def _is_infrastructure(self, src_mac, src_ip):
        if src_ip and src_ip in self._safe_ips:
            return True
        if self._gateway_mac and src_mac == self._gateway_mac:
            return True
        return False

    def _packet_summary(self, pkt):
        src_ip = None
        dst_ip = None
        proto = 'L2'
        dst_port = None

        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            proto = 'IP'
            if pkt.haslayer(TCP):
                proto = 'TCP'
                dst_port = int(pkt[TCP].dport)
            elif pkt.haslayer(UDP):
                proto = 'UDP'
                dst_port = int(pkt[UDP].dport)
        elif pkt.haslayer(ARP):
            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst
            proto = 'ARP'

        return src_ip, dst_ip, proto, dst_port

    def _update_inventory(self, now, src_mac, src_ip, dst_ip, proto, dst_port):
        device = self._devices.get(src_mac)
        if device is None:
            device = {
                'first_seen': now,
                'last_seen': now,
                'ips': set(),
                'protocols': set(),
                'dst_ports': set(),
                'dst_ips': set(),
                'packets': 0,
            }
            self._devices[src_mac] = device
            self.stats['new_devices'] += 1
            self.stats['devices'] = len(self._devices)

            if self.cfg.get('iot', {}).get('log_new_devices', True):
                ip_label = src_ip or 'N/A'
                self.info(f"IoT inventory: new device observed: {ip_label} / {src_mac}")

        device['last_seen'] = now
        device['packets'] += 1
        if src_ip:
            device['ips'].add(src_ip)
        if dst_ip:
            device['dst_ips'].add(dst_ip)
        if proto:
            device['protocols'].add(proto)
        if dst_port is not None:
            device['dst_ports'].add(dst_port)

    def _check_port_fanout(self, now, src_mac, src_ip, dst_ip, proto, dst_port):
        if dst_port is None:
            return

        cfg = self.cfg.get('iot', {})
        window_sec = int(cfg.get('fanout_window_sec', 300))
        port_threshold = int(cfg.get('fanout_port_threshold', 20))
        cooldown = int(cfg.get('alert_cooldown_sec', 300))

        window = self._port_windows[src_mac]
        window.append((now, dst_ip, dst_port, proto))
        while window and now - window[0][0] > window_sec:
            window.popleft()

        unique_ports = {entry[2] for entry in window}
        if len(unique_ports) < port_threshold:
            return

        if now - self._last_alert.get(src_mac, 0) < cooldown:
            return

        self._last_alert[src_mac] = now
        self.stats['anomalies'] += 1

        unique_dst_ips = {entry[1] for entry in window if entry[1]}
        features = {
            'mac': src_mac,
            'ip': src_ip,
            'unique_dst_ports': len(unique_ports),
            'unique_dst_ips': len(unique_dst_ips),
            'window_sec': window_sec,
            'protocol': proto,
        }
        msg = (
            f"IoT behavior anomaly: {src_ip or 'N/A'} / {src_mac} contacted "
            f"{len(unique_ports)} unique destination ports in {window_sec}s"
        )
        self.alert(
            message=msg,
            source_ip=src_ip,
            source_mac=src_mac,
            target_ip=dst_ip,
            confidence=0.70,
            features=features,
        )

    def _on_packet(self, pkt):
        if not pkt.haslayer(Ether):
            return

        now = time.time()
        self.stats['packets'] += 1
        src_mac = pkt[Ether].src.upper()
        src_ip, dst_ip, proto, dst_port = self._packet_summary(pkt)

        if src_ip == self._defense_ip or self._is_infrastructure(src_mac, src_ip):
            return

        self._update_inventory(now, src_mac, src_ip, dst_ip, proto, dst_port)
        self._check_port_fanout(now, src_mac, src_ip, dst_ip, proto, dst_port)

    def reset_state(self):
        self._devices.clear()
        self._port_windows.clear()
        self._last_alert.clear()
        for key in self.stats:
            self.stats[key] = 0

    def run(self):
        cfg = self.cfg
        iface = cfg['interface']
        self._iface = iface
        self._defense_ip = get_interface_ip(iface)
        self._safe_ips = collect_trusted_infrastructure_ips(cfg, iface)
        self._gateway_ip = get_default_gateway()
        self._gateway_mac = (
            get_default_gateway_mac(iface, self._gateway_ip)
            if self._gateway_ip else None
        )

        self._emit(f"[START] IoT profile detector v{self.VERSION} on {iface}")
        try:
            while not self.stop_event.is_set():
                sniff(
                    iface=iface,
                    prn=self._on_packet,
                    store=False,
                    filter="arp or ip",
                    timeout=2,
                    stop_filter=lambda _: self.stop_event.is_set(),
                )
        finally:
            self._emit("[STOP] IoT profile detector stopped")


_callback = None
stats = {'packets': 0, 'devices': 0, 'new_devices': 0, 'anomalies': 0}


def set_callback(fn):
    global _callback
    _callback = fn


def run_detector(cfg, stop_event=None):
    import threading
    det = IoTProfileDetector(cfg, stop_event or threading.Event(), _callback)
    det.run()
    stats.update(det.stats)


if __name__ == "__main__":
    import os
    import sys
    import threading

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from config import load_config

    run_detector(load_config())
