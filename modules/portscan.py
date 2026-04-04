#!/usr/bin/env python3
"""
TCP SYN port-scan detector.
Uses Scapy to sniff for rapid probes across many ports and blocks scanners.
"""

from scapy.all import sniff, IP, TCP, Ether
import time
from collections import defaultdict, deque

from modules.firewall import ensure_chain, flush_chain, block_ip, run, ts
from modules.netutil import get_interface_ip
from modules.detected_mac_persist import persist as persist_detected_mac

CHAIN = "NIDS_PORTSCAN"

seen_ports = defaultdict(deque)
seen_syns = defaultdict(deque)
blocked_ips = set()

_callback = None
_defense_ip = None
_cfg = None
_start_time = None


def set_callback(fn):
    global _callback
    _callback = fn


def _emit(msg):
    line = f"{ts()} {msg}"
    if _callback:
        _callback(line)
    else:
        print(line, flush=True)


def _cleanup_old(src, now, window):
    while seen_ports[src] and (now - seen_ports[src][0][0]) > window:
        seen_ports[src].popleft()
    while seen_syns[src] and (now - seen_syns[src][0]) > window:
        seen_syns[src].popleft()


def _on_packet(pkt):
    now = time.time()
    if now - _start_time < 1:
        return
    if not (IP in pkt and TCP in pkt):
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    dport = int(pkt[TCP].dport)

    if dst != _defense_ip or src == _defense_ip:
        return

    if src in blocked_ips:
        return
    if pkt[TCP].flags != "S":
        return

    window = _cfg["portscan"]["window_sec"]
    port_thr = _cfg["portscan"]["port_threshold"]
    syn_thr = _cfg["portscan"]["syn_threshold"]

    seen_ports[src].append((now, dport))
    seen_syns[src].append(now)
    _cleanup_old(src, now, window)

    unique_ports = {p for _, p in seen_ports[src]}
    syn_count = len(seen_syns[src])

    if len(unique_ports) >= port_thr and syn_count >= syn_thr:
        src_mac = pkt[Ether].src.upper() if pkt.haslayer(Ether) else "unknown"
        _emit(f"[ALERT] Port scan from {src} / {src_mac} ({len(unique_ports)} ports / {syn_count} SYNs in {window}s)")
        block_ip(CHAIN, src)
        blocked_ips.add(src)
        if src_mac != "unknown":
            persist_detected_mac(src_mac, src, _emit)
        _emit(f"[BLOCK] Blocked {src}")
        seen_ports[src].clear()
        seen_syns[src].clear()


def run_detector(cfg, stop_event=None):
    """Main loop -- runs until stop_event is set."""
    global _cfg, _defense_ip, _start_time

    _cfg = cfg
    iface = cfg["interface"]
    _defense_ip = get_interface_ip(iface)
    _start_time = time.time()

    seen_ports.clear()
    seen_syns.clear()
    blocked_ips.clear()

    ensure_chain(CHAIN)
    flush_chain(CHAIN)

    syn_thr = cfg["portscan"]["syn_threshold"]
    window = cfg["portscan"]["window_sec"]
    run(["sudo", "iptables", "-A", CHAIN, "-p", "tcp", "--syn", "-m", "recent",
         "--name", "nids_ps", "--set"])
    run(["sudo", "iptables", "-A", CHAIN, "-p", "tcp", "--syn", "-m", "recent",
         "--name", "nids_ps", "--rcheck", "--seconds", str(window),
         "--hitcount", str(syn_thr), "-j", "DROP"])

    _emit(f"[START] Port-scan detector on {iface} (IP: {_defense_ip})")

    try:
        while stop_event is None or not stop_event.is_set():
            sniff(
                iface=iface,
                prn=_on_packet,
                store=False,
                filter="tcp",
                timeout=2,
                stop_filter=lambda _: stop_event is not None and stop_event.is_set(),
            )
    finally:
        flush_chain(CHAIN)
        _emit("[STOP] Port-scan detector stopped")


if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from config import load_config
    run_detector(load_config())
