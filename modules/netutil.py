#!/usr/bin/env python3
"""
Network utility helpers (interface IP, netmask, gateway, etc.).
"""

import socket
import fcntl
import struct
import subprocess
import ipaddress


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
