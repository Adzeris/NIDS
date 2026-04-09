#!/usr/bin/env python3
"""
Shared iptables helpers used by all detection modules.
"""

import subprocess
import time


def run(cmd):
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def ensure_chain(chain):
    run(["sudo", "iptables", "-N", chain])
    chk = subprocess.run(
        ["sudo", "iptables", "-C", "INPUT", "-j", chain],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if chk.returncode != 0:
        run(["sudo", "iptables", "-I", "INPUT", "1", "-j", chain])


def ensure_chain_iface(chain, iface):
    run(["sudo", "iptables", "-N", chain])
    chk = subprocess.run(
        ["sudo", "iptables", "-C", "INPUT", "-i", iface, "-j", chain],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if chk.returncode != 0:
        run(["sudo", "iptables", "-I", "INPUT", "1", "-i", iface, "-j", chain])


def flush_chain(chain):
    run(["sudo", "iptables", "-F", chain])


def delete_hook(chain, iface=None):
    while True:
        if iface:
            res = subprocess.run(
                ["sudo", "iptables", "-D", "INPUT", "-i", iface, "-j", chain],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            res = subprocess.run(
                ["sudo", "iptables", "-D", "INPUT", "-j", chain],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        if res.returncode != 0:
            break


def destroy_chain(chain):
    """Fully remove a chain: flush rules, remove INPUT hooks, delete chain."""
    flush_chain(chain)
    delete_hook(chain)
    run(["sudo", "iptables", "-X", chain])


def block_ip(chain, ip):
    run(["sudo", "iptables", "-I", chain, "1", "-s", ip, "-j", "DROP"])


def unblock_ip(chain, ip):
    while True:
        res = subprocess.run(
            ["sudo", "iptables", "-D", chain, "-s", ip, "-j", "DROP"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if res.returncode != 0:
            break


def block_mac(chain, mac):
    run(["sudo", "iptables", "-I", chain, "1", "-m", "mac", "--mac-source", mac, "-j", "DROP"])


def unblock_mac(chain, mac):
    while True:
        res = subprocess.run(
            ["sudo", "iptables", "-D", chain, "-m", "mac", "--mac-source", mac, "-j", "DROP"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if res.returncode != 0:
            break


def log_rule(chain, src, prefix):
    run(["sudo", "iptables", "-A", chain, "-s", src, "-j", "LOG", "--log-prefix", prefix])
    run(["sudo", "iptables", "-A", chain, "-s", src, "-j", "DROP"])


def list_blocked_ips(chain):
    """Return set of IPs blocked via -s <ip> -j DROP in the given chain."""
    import re
    result = set()
    try:
        proc = subprocess.run(
            ["sudo", "iptables", "-S", chain],
            capture_output=True, text=True, timeout=5,
        )
        if proc.returncode != 0:
            return result
        for line in proc.stdout.splitlines():
            m = re.match(r'-A\s+\S+\s+-s\s+([\d.]+)(?:/32)?\s+-j\s+DROP', line)
            if m:
                result.add(m.group(1))
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return result


def list_blocked_macs(chain):
    """Return set of MACs blocked via --mac-source <mac> -j DROP."""
    import re
    result = set()
    try:
        proc = subprocess.run(
            ["sudo", "iptables", "-S", chain],
            capture_output=True, text=True, timeout=5,
        )
        if proc.returncode != 0:
            return result
        for line in proc.stdout.splitlines():
            m = re.search(r'--mac-source\s+([\dA-Fa-f:]{17})\s+-j\s+DROP', line)
            if m:
                result.add(m.group(1).upper())
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return result


def ts():
    return time.strftime("%Y-%m-%d %H:%M:%S")
