#!/usr/bin/env python3
"""
MAC address filter module.
Supports whitelist mode (only listed MACs allowed) and blacklist mode (listed MACs blocked). 
Uses Scapy to inspect Ethernet headers and iptables mac-match to enforce.
"""

from scapy.all import sniff, Ether, IP
import time

from modules.firewall import ensure_chain, flush_chain, block_mac, unblock_mac, ts
from modules.detected_mac_persist import persist as persist_detected_mac

CHAIN = "NIDS_MACFILTER"

_callback = None
_blocked_macs = set()
_alerted_macs = set()


def set_callback(fn):
    global _callback
    _callback = fn


def _emit(msg):
    line = f"{ts()} {msg}"
    if _callback:
        _callback(line)
    else:
        print(line, flush=True)


def _on_packet(pkt, cfg):
    if not pkt.haslayer(Ether):
        return

    src_mac = pkt[Ether].src.upper()
    mode = cfg["macfilter"]["mode"]
    allowed = {m.upper() for m in cfg["macfilter"]["allowed_macs"]}
    deny = {m.upper() for m in cfg["macfilter"]["blocked_macs"]}

    should_block = False

    if mode == "whitelist":
        if allowed and src_mac not in allowed:
            should_block = True
    elif mode == "blacklist":
        if src_mac in deny:
            should_block = True

    if should_block and src_mac not in _blocked_macs:
        src_ip = pkt[IP].src if pkt.haslayer(IP) else "N/A"
        _emit(f"[ALERT] Unauthorised MAC {src_mac} (IP: {src_ip}) — blocking")
        block_mac(CHAIN, src_mac)
        _blocked_macs.add(src_mac)
        persist_detected_mac(src_mac, src_ip, _emit)
        _emit(f"[BLOCK] MAC {src_mac} dropped via {CHAIN}")

    if not should_block and src_mac in _blocked_macs:
        unblock_mac(CHAIN, src_mac)
        _blocked_macs.discard(src_mac)
        _emit(f"[UNBLOCK] MAC {src_mac} removed from block list")


def run_detector(cfg, stop_event=None):
    """Main loop -- runs until stop_event is set."""
    iface = cfg["interface"]
    mode = cfg["macfilter"]["mode"]

    _blocked_macs.clear()
    _alerted_macs.clear()

    ensure_chain(CHAIN)
    flush_chain(CHAIN)

    mode_label = "Allow Only" if mode == "whitelist" else "Block Only"
    _emit(f"[START] MAC filter on {iface} (mode: {mode_label})")

    if mode == "whitelist":
        macs = cfg["macfilter"]["allowed_macs"]
        if macs:
            _emit(f"[INFO] Allowed MACs: {', '.join(macs)}")
        else:
            _emit("[INFO] Allowed list empty — all MACs permitted (add MACs to enforce)")
    else:
        macs = cfg["macfilter"]["blocked_macs"]
        if macs:
            _emit(f"[INFO] Blocked MACs: {', '.join(macs)}")

    try:
        while stop_event is None or not stop_event.is_set():
            sniff(
                iface=iface,
                prn=lambda pkt: _on_packet(pkt, cfg),
                store=False,
                timeout=2,
                stop_filter=lambda _: stop_event is not None and stop_event.is_set(),
            )
    finally:
        flush_chain(CHAIN)
        _emit("[STOP] MAC filter stopped")


if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from config import load_config
    run_detector(load_config())
