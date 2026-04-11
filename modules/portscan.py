#!/usr/bin/env python3
"""
TCP SYN + UDP port-scan detector.
Uses Scapy to sniff for rapid probes across many ports and blocks scanners.
"""

from scapy.all import sniff, IP, TCP, UDP, Ether
import time
from collections import defaultdict, deque

from modules.firewall import ensure_chain, flush_chain, block_ip, run, ts
from modules.netutil import get_interface_ip, get_default_gateway
from modules.detected_mac_persist import persist as persist_detected_mac

CHAIN = "NIDS_PORTSCAN"

# TCP SYN tracking
seen_ports = defaultdict(deque)
seen_syns = defaultdict(deque)
slow_seen_ports = defaultdict(deque)
slow_seen_syns = defaultdict(deque)

# UDP tracking
udp_seen_ports = defaultdict(deque)
udp_seen_probes = defaultdict(deque)

blocked_ips = set()

_callback = None
_defense_ip = None
_safe_ips = set()
_cfg = None
_start_time = None
stats = {"syn_packets": 0, "udp_packets": 0, "blocks": 0}


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


def _cleanup_slow(src, now, window):
    while slow_seen_ports[src] and (now - slow_seen_ports[src][0][0]) > window:
        slow_seen_ports[src].popleft()
    while slow_seen_syns[src] and (now - slow_seen_syns[src][0]) > window:
        slow_seen_syns[src].popleft()


def _cleanup_udp(src, now, window):
    while udp_seen_ports[src] and (now - udp_seen_ports[src][0][0]) > window:
        udp_seen_ports[src].popleft()
    while udp_seen_probes[src] and (now - udp_seen_probes[src][0]) > window:
        udp_seen_probes[src].popleft()


def _block_scan(src, pkt, unique_ports, count, window, label):
    src_mac = pkt[Ether].src.upper() if pkt.haslayer(Ether) else "unknown"
    proto = "UDP probes" if "UDP" in label else "SYNs"
    _emit(
        f"[ALERT] {label} scan from {src} / {src_mac} "
        f"({len(unique_ports)} ports / {count} {proto} in {window}s)"
    )
    if src_mac != "unknown":
        persist_detected_mac(src_mac, src, _emit)
    if src in _safe_ips:
        _emit(f"[WARN] {src} is the gateway/whitelisted — alerting only (blocking would break connectivity)")
    else:
        block_ip(CHAIN, src)
        blocked_ips.add(src)
        stats["blocks"] += 1
        _emit(f"[BLOCK] Blocked {src}")
    seen_ports[src].clear()
    seen_syns[src].clear()
    slow_seen_ports[src].clear()
    slow_seen_syns[src].clear()
    udp_seen_ports[src].clear()
    udp_seen_probes[src].clear()


def _handle_tcp(pkt, src, dst, now):
    if pkt[TCP].flags != "S":
        return

    dport = int(pkt[TCP].dport)
    if dst != _defense_ip or src == _defense_ip:
        return

    window = _cfg["portscan"]["window_sec"]
    port_thr = _cfg["portscan"]["port_threshold"]
    syn_thr = _cfg["portscan"]["syn_threshold"]
    slow_window = _cfg["portscan"].get("slow_window_sec", 120)
    slow_port_thr = _cfg["portscan"].get("slow_port_threshold", port_thr)
    slow_syn_thr = _cfg["portscan"].get("slow_syn_threshold", syn_thr)

    stats["syn_packets"] += 1
    seen_ports[src].append((now, dport))
    seen_syns[src].append(now)
    slow_seen_ports[src].append((now, dport))
    slow_seen_syns[src].append(now)
    _cleanup_old(src, now, window)
    _cleanup_slow(src, now, slow_window)

    unique_ports = {p for _, p in seen_ports[src]}
    syn_count = len(seen_syns[src])
    slow_unique = {p for _, p in slow_seen_ports[src]}
    slow_count = len(slow_seen_syns[src])

    if len(unique_ports) >= port_thr and syn_count >= syn_thr:
        _block_scan(src, pkt, unique_ports, syn_count, window, "TCP port")
        return

    if len(slow_unique) >= slow_port_thr and slow_count >= slow_syn_thr:
        _block_scan(src, pkt, slow_unique, slow_count, slow_window, "Slow TCP")


def _handle_udp(pkt, src, dst, now):
    dport = int(pkt[UDP].dport)
    if dst != _defense_ip or src == _defense_ip:
        return

    udp_window = _cfg["portscan"].get("udp_window_sec", 10)
    udp_port_thr = _cfg["portscan"].get("udp_port_threshold", 8)
    udp_probe_thr = _cfg["portscan"].get("udp_probe_threshold", 12)

    stats["udp_packets"] += 1
    udp_seen_ports[src].append((now, dport))
    udp_seen_probes[src].append(now)
    _cleanup_udp(src, now, udp_window)

    unique_ports = {p for _, p in udp_seen_ports[src]}
    probe_count = len(udp_seen_probes[src])

    if len(unique_ports) >= udp_port_thr and probe_count >= udp_probe_thr:
        _block_scan(src, pkt, unique_ports, probe_count, udp_window, "UDP port")


def _on_packet(pkt):
    now = time.time()
    if now - _start_time < 1:
        return
    if IP not in pkt:
        return

    src = pkt[IP].src
    dst = pkt[IP].dst

    if src in blocked_ips:
        return

    if TCP in pkt:
        _handle_tcp(pkt, src, dst, now)
    elif UDP in pkt:
        _handle_udp(pkt, src, dst, now)


def _build_safe_ips(cfg, iface):
    safe = {"0.0.0.0", "255.255.255.255"}
    if cfg.get("network_mode", "nat") == "bridged":
        gw = get_default_gateway(iface)
        if gw and cfg.get("spoof", {}).get("gateway_auto_whitelist", True):
            safe.add(gw)
        if cfg.get("spoof", {}).get("whitelist_host") and cfg.get("spoof", {}).get("host_ip", "").strip():
            safe.add(cfg["spoof"]["host_ip"].strip())
    for ip_str in cfg.get("spoof", {}).get("whitelist_ips", []):
        safe.add(ip_str.strip())
    return safe


def run_detector(cfg, stop_event=None):
    """Main loop -- runs until stop_event is set."""
    global _cfg, _defense_ip, _safe_ips, _start_time

    _cfg = cfg
    iface = cfg["interface"]
    _defense_ip = get_interface_ip(iface)
    _safe_ips = _build_safe_ips(cfg, iface)
    _start_time = time.time()

    seen_ports.clear()
    seen_syns.clear()
    slow_seen_ports.clear()
    slow_seen_syns.clear()
    udp_seen_ports.clear()
    udp_seen_probes.clear()
    blocked_ips.clear()
    stats["syn_packets"] = 0
    stats["udp_packets"] = 0
    stats["blocks"] = 0

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
                filter="tcp or udp",
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
