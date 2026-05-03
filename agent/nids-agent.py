#!/usr/bin/env python3
"""
NIDS IoT endpoint agent.

Runs on Linux-based IoT devices without the PyQt GUI. The agent keeps the
footprint small by using only the Python standard library and Linux proc/sysfs
interfaces. It can log locally and optionally POST JSON events to a controller.
"""

import argparse
import json
import os
import platform
import re
import socket
import time
import urllib.error
import urllib.request
from collections import defaultdict, deque
from pathlib import Path


DEFAULT_CONFIG = {
    "agent_id": "auto",
    "controller_url": "",
    "monitor_interval_sec": 5,
    "local_log": True,
    "log_path": "/var/log/nids-agent/events.jsonl",
    "auth_log_paths": ["/var/log/auth.log", "/var/log/secure"],
    "interfaces": ["auto"],
    "thresholds": {
        "failed_login_window_sec": 300,
        "failed_login_threshold": 5,
        "port_fanout_window_sec": 300,
        "port_fanout_threshold": 20,
        "pps_threshold": 1000,
    },
}

FAILED_LOGIN_RE = re.compile(
    r"(Failed password|authentication failure|Invalid user|failed login)",
    re.IGNORECASE,
)
REMOTE_IP_RE = re.compile(r"from\s+(\d{1,3}(?:\.\d{1,3}){3})")


def deep_merge(base, override):
    result = json.loads(json.dumps(base))
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path):
    if not path.exists():
        return DEFAULT_CONFIG
    with path.open("r", encoding="utf-8") as f:
        return deep_merge(DEFAULT_CONFIG, json.load(f))


def primary_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "0.0.0.0"
    finally:
        sock.close()


def interface_macs():
    result = {}
    for iface_path in Path("/sys/class/net").glob("*"):
        iface = iface_path.name
        if iface == "lo":
            continue
        addr_path = iface_path / "address"
        if addr_path.exists():
            mac = addr_path.read_text(encoding="utf-8").strip().upper()
            result[iface] = mac
    return result


def build_identity(cfg):
    macs = interface_macs()
    agent_id = cfg.get("agent_id") or "auto"
    if agent_id == "auto":
        first_mac = next(iter(macs.values()), "UNKNOWN")
        agent_id = f"{socket.gethostname()}-{first_mac.replace(':', '')}"
    return {
        "agent_id": agent_id,
        "hostname": socket.gethostname(),
        "ip": primary_ip(),
        "interfaces": macs,
        "platform": platform.platform(),
        "machine": platform.machine(),
    }


def parse_proc_net(path, proto):
    rows = []
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()[1:]
    except OSError:
        return rows

    for line in lines:
        parts = line.split()
        if len(parts) < 3:
            continue
        local_hex, remote_hex, state = parts[1], parts[2], parts[3] if proto == "tcp" else ""
        remote_ip_hex, remote_port_hex = remote_hex.split(":")
        remote_port = int(remote_port_hex, 16)
        if remote_port == 0:
            continue
        remote_ip = ".".join(str(int(remote_ip_hex[i:i + 2], 16)) for i in (6, 4, 2, 0))
        rows.append({
            "proto": proto.upper(),
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "state": state,
            "local": local_hex,
        })
    return rows


def read_net_counters():
    counters = {}
    try:
        lines = Path("/proc/net/dev").read_text(encoding="utf-8").splitlines()[2:]
    except OSError:
        return counters

    for line in lines:
        iface, data = line.split(":", 1)
        iface = iface.strip()
        if iface == "lo":
            continue
        parts = data.split()
        if len(parts) >= 10:
            counters[iface] = {
                "rx_packets": int(parts[1]),
                "tx_packets": int(parts[9]),
            }
    return counters


class Agent:
    def __init__(self, cfg):
        self.cfg = cfg
        self.identity = build_identity(cfg)
        self.auth_offsets = {}
        self.failed_logins = deque()
        self.port_window = defaultdict(deque)
        self.last_net = None
        self.last_net_ts = None
        self.last_alert = {}

    def emit(self, event_type, message, severity="info", features=None):
        event = {
            "timestamp": time.time(),
            "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "event_type": event_type,
            "severity": severity,
            "message": message,
            "agent": self.identity,
            "features": features or {},
        }
        line = json.dumps(event, sort_keys=True)

        if self.cfg.get("local_log", True):
            log_path = Path(self.cfg.get("log_path", DEFAULT_CONFIG["log_path"]))
            try:
                log_path.parent.mkdir(parents=True, exist_ok=True)
                with log_path.open("a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except OSError:
                print(line, flush=True)
        else:
            print(line, flush=True)

        self.report(event)

    def report(self, event):
        url = self.cfg.get("controller_url", "").strip()
        if not url:
            return
        data = json.dumps(event).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=3).read()
        except (urllib.error.URLError, TimeoutError, OSError):
            pass

    def check_auth_logs(self):
        now = time.time()
        threshold = self.cfg["thresholds"]["failed_login_threshold"]
        window_sec = self.cfg["thresholds"]["failed_login_window_sec"]

        for log_name in self.cfg.get("auth_log_paths", []):
            path = Path(log_name)
            if not path.exists():
                continue
            try:
                size = path.stat().st_size
                offset = self.auth_offsets.get(str(path), size)
                if size < offset:
                    offset = 0
                with path.open("r", encoding="utf-8", errors="ignore") as f:
                    f.seek(offset)
                    lines = f.readlines()
                    self.auth_offsets[str(path)] = f.tell()
            except OSError:
                continue

            for line in lines:
                if not FAILED_LOGIN_RE.search(line):
                    continue
                ip_match = REMOTE_IP_RE.search(line)
                remote_ip = ip_match.group(1) if ip_match else "unknown"
                self.failed_logins.append((now, remote_ip))

        while self.failed_logins and now - self.failed_logins[0][0] > window_sec:
            self.failed_logins.popleft()

        by_ip = defaultdict(int)
        for _, remote_ip in self.failed_logins:
            by_ip[remote_ip] += 1

        for remote_ip, count in by_ip.items():
            key = f"auth:{remote_ip}"
            if count >= threshold and now - self.last_alert.get(key, 0) > window_sec:
                self.last_alert[key] = now
                self.emit(
                    "FAILED_LOGIN_BURST",
                    f"{count} failed login events from {remote_ip} in {window_sec}s",
                    severity="warning",
                    features={"remote_ip": remote_ip, "count": count, "window_sec": window_sec},
                )

    def check_connections(self):
        now = time.time()
        threshold = self.cfg["thresholds"]["port_fanout_threshold"]
        window_sec = self.cfg["thresholds"]["port_fanout_window_sec"]

        conns = parse_proc_net("/proc/net/tcp", "tcp") + parse_proc_net("/proc/net/udp", "udp")
        for conn in conns:
            key = conn["remote_ip"]
            self.port_window[key].append((now, conn["remote_port"], conn["proto"]))
            while self.port_window[key] and now - self.port_window[key][0][0] > window_sec:
                self.port_window[key].popleft()

            ports = {port for _, port, _ in self.port_window[key]}
            alert_key = f"fanout:{key}"
            if len(ports) >= threshold and now - self.last_alert.get(alert_key, 0) > window_sec:
                self.last_alert[alert_key] = now
                self.emit(
                    "PORT_FANOUT",
                    f"Device contacted {len(ports)} unique remote ports on {key} in {window_sec}s",
                    severity="warning",
                    features={"remote_ip": key, "unique_ports": len(ports), "window_sec": window_sec},
                )

    def check_packet_rate(self):
        now = time.time()
        current = read_net_counters()
        if self.last_net is None:
            self.last_net = current
            self.last_net_ts = now
            return

        elapsed = max(now - self.last_net_ts, 1)
        threshold = self.cfg["thresholds"]["pps_threshold"]
        for iface, counters in current.items():
            previous = self.last_net.get(iface)
            if not previous:
                continue
            packets = (
                counters["rx_packets"] + counters["tx_packets"]
                - previous["rx_packets"] - previous["tx_packets"]
            )
            pps = packets / elapsed
            alert_key = f"pps:{iface}"
            if pps >= threshold and now - self.last_alert.get(alert_key, 0) > 60:
                self.last_alert[alert_key] = now
                self.emit(
                    "HIGH_PACKET_RATE",
                    f"High packet rate on {iface}: {pps:.1f} packets/sec",
                    severity="warning",
                    features={"interface": iface, "pps": round(pps, 2), "threshold": threshold},
                )

        self.last_net = current
        self.last_net_ts = now

    def run(self):
        self.emit("AGENT_START", "NIDS IoT agent started", features={"config": "loaded"})
        interval = max(int(self.cfg.get("monitor_interval_sec", 5)), 1)
        while True:
            self.check_auth_logs()
            self.check_connections()
            self.check_packet_rate()
            time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description="NIDS IoT endpoint agent")
    parser.add_argument(
        "-c", "--config",
        default=os.environ.get("NIDS_AGENT_CONFIG", "/etc/nids-agent/agent_config.json"),
        help="Path to agent config JSON",
    )
    args = parser.parse_args()
    cfg = load_config(Path(args.config))
    Agent(cfg).run()


if __name__ == "__main__":
    main()
