#!/usr/bin/env python3
"""
Network utility helpers (interface IP, netmask, gateway, etc.).
"""

import socket
import fcntl
import struct
import subprocess
import ipaddress
import os


def get_interface_ip(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(
        fcntl.ioctl(
            s.fileno(),
            0x8915,
            struct.pack("256s", ifname[:15].encode("utf-8")),
        )[20:24]
    )


def get_interface_netmask(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(
        fcntl.ioctl(
            s.fileno(),
            0x891B,
            struct.pack("256s", ifname[:15].encode("utf-8")),
        )[20:24]
    )


def get_local_network(ifname):
    ip = get_interface_ip(ifname)
    mask = get_interface_netmask(ifname)
    return ipaddress.ip_network(f"{ip}/{mask}", strict=False)


def get_default_gateway(ifname=None):
    """Return the default gateway IP for the given interface (or global default).

    Parses /proc/net/route which is always available on Linux.
    Returns None if no gateway is found.
    """
    try:
        with open("/proc/net/route", "r") as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if len(parts) < 3:
                    continue
                iface_name, dest, gw = parts[0], parts[1], parts[2]
                if dest != "00000000":
                    continue
                if ifname and iface_name != ifname:
                    continue
                gw_bytes = bytes.fromhex(gw)
                return socket.inet_ntoa(gw_bytes[::-1])
    except Exception:
        pass
    try:
        cmd = ["ip", "route", "show", "default"]
        if ifname:
            cmd += ["dev", ifname]
        out = subprocess.check_output(cmd, text=True, timeout=5)
        for line in out.splitlines():
            parts = line.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except Exception:
        pass
    return None


def collect_trusted_infrastructure_ips(cfg, iface):
    """
    IP addresses the detectors should not *block* when they are the source:
    local gateway (optional), optional bridged host, and manual whitelist.
    (Alerts may still be logged depending on the module; see detect_only in research.)
    """
    sp = cfg.get('spoof', {})
    out = {'0.0.0.0', '255.255.255.255'}
    if sp.get('whitelist_default_gateway', True):
        gw = get_default_gateway(iface)
        if gw:
            out.add(gw)
    if cfg.get('network_mode', 'nat') == 'bridged':
        host = sp.get('host_ip', '').strip()
        if sp.get('whitelist_host') and host:
            out.add(host)
    for s in sp.get('whitelist_ips', []):
        s = s.strip()
        if s:
            out.add(s)
    return out


def get_neighbor_mac(ip, ifname):
    """
    L2 (MAC) address for an IPv4 neighbor, if the kernel has one on this interface.
    Used so policy modules can recognize frames that arrived via the default gateway
    (L3 src may be a remote host while Ethernet src is the router's MAC).
    """
    if not ip or not ifname:
        return None
    try:
        out = subprocess.check_output(
            ["ip", "neigh", "show", ip, "dev", ifname], text=True, timeout=3
        )
        for line in out.splitlines():
            parts = line.split()
            if "lladdr" in parts:
                i = parts.index("lladdr")
                if i + 1 < len(parts):
                    return parts[i + 1].upper()
    except Exception:
        pass
    try:
        with open("/proc/net/arp", "r", encoding="utf-8", errors="replace") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 6 and parts[0] == ip and parts[5] == ifname:
                    return parts[3].upper()
    except Exception:
        pass
    return None


def get_default_gateway_mac(ifname, gw_ip=None):
    """
    MAC address of the default gateway for this interface, if resolvable.
    """
    g = gw_ip or get_default_gateway(ifname)
    if not g:
        return None
    return get_neighbor_mac(g, ifname)


def list_interfaces():
    """Return known interface names."""
    names = []
    try:
        names = [name for _, name in socket.if_nameindex()]
    except OSError:
        names = []
    if not names:
        try:
            names = os.listdir("/sys/class/net")
        except OSError:
            names = []
    return sorted(set(n for n in names if n))


def interface_exists(ifname):
    """True when an interface name exists on this host."""
    if not ifname:
        return False
    return ifname in set(list_interfaces())


def get_default_interface():
    """Return Linux default-route interface name, if available."""
    try:
        with open("/proc/net/route", "r") as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if len(parts) < 2:
                    continue
                iface_name, dest = parts[0], parts[1]
                if dest == "00000000":
                    return iface_name
    except Exception:
        pass

    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"], text=True, timeout=5
        )
        for line in out.splitlines():
            parts = line.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return None


def resolve_capture_interface(preferred):
    """Resolve capture interface from config, with safe fallbacks.

    Returns:
      (iface_or_none, info_message_or_none)
    """
    pref = (preferred or "").strip()
    pref_is_auto = (not pref) or pref.lower() == "auto"

    if not pref_is_auto and interface_exists(pref):
        return pref, None

    default_iface = get_default_interface()
    if default_iface and interface_exists(default_iface):
        if pref_is_auto:
            return default_iface, f"Auto-selected interface '{default_iface}'"
        return (
            default_iface,
            f"Configured interface '{pref}' not found; using '{default_iface}'",
        )

    candidates = [i for i in list_interfaces() if i != "lo"]
    if candidates:
        chosen = candidates[0]
        if pref_is_auto:
            return chosen, f"Auto-selected interface '{chosen}'"
        return (
            chosen,
            f"Configured interface '{pref}' not found; using '{chosen}'",
        )

    if interface_exists("lo"):
        if pref_is_auto:
            return "lo", "No non-loopback interface found; using loopback (lo)"
        return "lo", f"Configured interface '{pref}' not found; using loopback (lo)"

    return None, "No usable network interfaces found on this system"
