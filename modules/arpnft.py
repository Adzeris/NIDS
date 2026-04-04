#!/usr/bin/env python3
"""
Drop traffic from blocked source MACs at L2 ingress (netdev), so ARP and all
Ethernet frames are dropped before the host processes them. The older
`arp` family hook often misses ARP replies on some kernels/setups.
"""

import subprocess
import shutil

# netdev = ingress on the NIDS interface (drops Ethernet before ARP/IP stack)
TABLE = "nids_nd"
SET_NAME = "blocked_macs"
CHAIN = "ingress"

_bound_iface = None


def _nft(args):
    return subprocess.run(
        ["sudo", "nft"] + args,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def nft_available():
    return shutil.which("nft") is not None


def _delete_legacy_arp_table():
    _nft(["delete", "table", "arp", "nids_arp"])


def _ensure_netdev(iface):
    """Create netdev ingress chain on iface; recreate if iface changed."""
    global _bound_iface
    if not nft_available() or not iface:
        return False

    _delete_legacy_arp_table()

    if _bound_iface != iface:
        _nft(["delete", "table", "netdev", TABLE])
        _bound_iface = iface

    chk = subprocess.run(
        ["sudo", "nft", "list", "table", "netdev", TABLE],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if chk.returncode == 0:
        return True

    _nft(["add", "table", "netdev", TABLE])
    _nft(
        [
            "add", "set", "netdev", TABLE, SET_NAME,
            "{", "type", "ether_addr", ";", "}",
        ]
    )
    _nft(
        [
            "add", "chain", "netdev", TABLE, CHAIN,
            "{",
            "type", "filter", "hook", "ingress", "device", iface, "priority", "0", ";",
            "policy", "accept", ";",
            "}",
        ]
    )
    _nft(
        [
            "add", "rule", "netdev", TABLE, CHAIN,
            "ether", "saddr", f"@{SET_NAME}", "drop",
        ]
    )
    return (
        subprocess.run(
            ["sudo", "nft", "list", "table", "netdev", TABLE],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        == 0
    )


def _norm_mac(mac):
    return mac.strip().lower()


def arp_block_mac(mac, iface):
    """Drop all Ethernet from this source MAC on ingress to iface."""
    if not _ensure_netdev(iface):
        return False
    m = _norm_mac(mac)
    r = _nft(["add", "element", "netdev", TABLE, SET_NAME, "{", m, "}"])
    return r.returncode == 0


def arp_unblock_mac(mac):
    if not nft_available():
        return False
    m = _norm_mac(mac)
    _nft(["delete", "element", "netdev", TABLE, SET_NAME, "{", m, "}"])
    return True


def arp_flush_blocked():
    if not nft_available():
        return False
    chk = subprocess.run(
        ["sudo", "nft", "list", "set", "netdev", TABLE, SET_NAME],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if chk.returncode != 0:
        return True
    _nft(["flush", "set", "netdev", TABLE, SET_NAME])
    return True


def arp_destroy_table():
    if not nft_available():
        return False
    _nft(["delete", "table", "netdev", TABLE])
    _delete_legacy_arp_table()
    global _bound_iface
    _bound_iface = None
    return True
