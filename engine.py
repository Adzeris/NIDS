#!/usr/bin/env python3
"""
NIDS engine v5.0 — research-aware central orchestrator.

Instantiates class-based detectors, manages threads, and collects
structured research events.  Each run carries:
  - run_id        unique identifier
  - config_hash   deterministic hash of the active config
  - git_commit    short commit hash (if available)
"""

import threading
import signal
import subprocess
import sys
import os
import time
import json
import re
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import load_config
from modules.detector_base import config_hash as _config_hash
from modules.host_network import resolve_capture_interface

from modules.portscan import PortScanDetector
from modules.bruteforce import BruteForceDetector
from modules.dos import DoSDetector
from modules.spoof import SpoofDetector
from modules.macfilter import MACFilterDetector
from modules.iot_profile import IoTProfileDetector


DETECTOR_CLASSES = {
    "portscan":   PortScanDetector,
    "bruteforce": BruteForceDetector,
    "dos":        DoSDetector,
    "spoof":      SpoofDetector,
    "macfilter":  MACFilterDetector,
    "iot_profile": IoTProfileDetector,
}


def _git_commit():
    try:
        return subprocess.check_output(
            ['git', 'rev-parse', '--short', 'HEAD'],
            stderr=subprocess.DEVNULL, text=True,
            cwd=os.path.dirname(os.path.abspath(__file__)),
        ).strip()
    except Exception:
        return 'unknown'


class NIDSEngine:
    """Central engine that manages detector instances and funnels their log output through a single callback. """

    def __init__(self, cfg=None, log_callback=None):
        self.cfg = cfg or load_config()
        self.log_callback = log_callback or self._default_log
        self.stop_event = threading.Event()
        self._shutdown_complete = False
        self.threads = {}
        self.detectors = {}
        self._lock = threading.Lock()
        self._log_lines = []
        self._structured_records = []

        # Research metadata
        self.run_id = time.strftime('%Y%m%d_%H%M%S') + '_' + uuid.uuid4().hex[:6]
        self.cfg_hash = _config_hash(self.cfg)
        self.git_commit = _git_commit()

        log_dir = self.cfg["logging"]["log_dir"]
        os.makedirs(log_dir, exist_ok=True)
        self._log_file = None
        self._jsonl_file = None
        if self.cfg["logging"]["log_to_file"]:
            stamp = time.strftime('%Y%m%d_%H%M%S')
            self._log_file = open(os.path.join(log_dir, f"nids_{stamp}.log"), "a")
            self._jsonl_file = open(os.path.join(log_dir, f"nids_{stamp}.jsonl"), "a")

    def _default_log(self, msg):
        print(msg, flush=True)

    # -- structured log parsing (backward-compatible) ----------------------

    _TAG_RE = re.compile(r'\[(\w+)\]')
    _IP_RE = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    _MAC_RE = re.compile(r'([\dA-Fa-f]{2}(?::[\dA-Fa-f]{2}){5})')

    def _parse_structured(self, msg):
        tag_m = self._TAG_RE.search(msg)
        event_type = tag_m.group(1) if tag_m else "INFO"
        ip_m = self._IP_RE.search(msg)
        mac_m = self._MAC_RE.search(msg)
        action = "alert" if event_type == "ALERT" else (
            "block" if event_type in ("BLOCK", "DETECT") else (
            "unblock" if event_type == "UNBLOCK" else "info"))
        return {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "run_id": self.run_id,
            "config_hash": self.cfg_hash,
            "event_type": event_type,
            "source_ip": ip_m.group(1) if ip_m else None,
            "source_mac": mac_m.group(1).upper() if mac_m else None,
            "action": action,
            "message": msg,
        }

    def _log(self, msg):
        record = self._parse_structured(msg)
        with self._lock:
            if self._shutdown_complete:
                return
            self._log_lines.append(msg)
            self._structured_records.append(record)
            if self._log_file:
                try:
                    self._log_file.write(msg + "\n")
                    self._log_file.flush()
                except (ValueError, OSError):
                    pass
            if self._jsonl_file:
                try:
                    self._jsonl_file.write(json.dumps(record) + "\n")
                    self._jsonl_file.flush()
                except (ValueError, OSError):
                    pass
        try:
            self.log_callback(msg)
        except (RuntimeError, OSError):
            pass

    # -- public accessors --------------------------------------------------

    def get_log_lines(self):
        with self._lock:
            return list(self._log_lines)

    def get_structured_records(self):
        with self._lock:
            return list(self._structured_records)

    def get_module_stats(self):
        result = {}
        for name, det in self.detectors.items():
            result[name] = dict(det.stats)
        return result

    def get_detector_events(self):
        """Collect structured research events from all detector instances."""
        events = []
        for det in self.detectors.values():
            events.extend(det.get_events())
        events.sort(key=lambda e: e['timestamp'])
        return events

    def get_run_metadata(self):
        return {
            'run_id': self.run_id,
            'config_hash': self.cfg_hash,
            'git_commit': self.git_commit,
            'method': self.cfg.get('research', {}).get('method', 'adaptive'),
            'detect_only': self.cfg.get('research', {}).get('detect_only', False),
        }

    # -- engine lifecycle --------------------------------------------------

    def start(self):
        enabled = dict(self.cfg["modules"])

        requested_iface = self.cfg.get('interface', '')
        resolved_iface, iface_note = resolve_capture_interface(requested_iface)
        if resolved_iface:
            self.cfg['interface'] = resolved_iface
            if requested_iface != resolved_iface:
                self.cfg_hash = _config_hash(self.cfg)
        else:
            # Modules that do packet capture cannot run without an interface.
            for mod in ("portscan", "dos", "spoof", "macfilter", "iot_profile"):
                if enabled.get(mod, False):
                    enabled[mod] = False
            self._log(f"{_ts()} [WARN] {iface_note}; capture modules disabled")

        if iface_note:
            self._log(f"{_ts()} [WARN] {iface_note}")

        self._log(f"{_ts()} [ENGINE] Starting NIDS v5.0 — interface: {self.cfg['interface']}")
        self._log(f"{_ts()} [ENGINE] Run: {self.run_id}  config: {self.cfg_hash}")

        for name, cls in DETECTOR_CLASSES.items():
            if not enabled.get(name, False):
                if name != "macfilter":
                    self._log(f"{_ts()} [ENGINE] {name} is disabled, skipping")
                continue

            detector = cls(self.cfg, self.stop_event, self._log)
            self.detectors[name] = detector

            t = threading.Thread(
                target=self._run_detector,
                args=(name, detector),
                daemon=True,
                name=f"nids-{name}",
            )
            t.start()
            self.threads[name] = t

        self._log(f"{_ts()} [ENGINE] All modules launched ({len(self.threads)} active)")

    def _run_detector(self, name, detector):
        try:
            detector.run()
        except OSError as e:
            if getattr(e, "errno", None) == 19:
                iface = self.cfg.get("interface", "unknown")
                self._log(
                    f"{_ts()} [ERROR] {name} crashed: interface '{iface}' is unavailable "
                    "(No such device)."
                )
            else:
                self._log(f"{_ts()} [ERROR] {name} crashed: {e}")
        except Exception as e:
            self._log(f"{_ts()} [ERROR] {name} crashed: {e}")

    def stop(self):
        self._log(f"{_ts()} [ENGINE] Shutting down...")
        self.stop_event.set()

        for name, t in self.threads.items():
            t.join(timeout=4)
            if t.is_alive():
                self._log(f"{_ts()} [WARN] {name} thread did not stop cleanly")

        self.flush_dns()
        self._log(f"{_ts()} [ENGINE] Stopped")

        with self._lock:
            self._shutdown_complete = True
            for f in (self._log_file, self._jsonl_file):
                if f:
                    try:
                        f.close()
                    except (ValueError, OSError):
                        pass
            self._log_file = None
            self._jsonl_file = None

    def reset_detectors(self):
        """Reset all detector runtime state (used by GUI Unblock All)."""
        for det in self.detectors.values():
            det.reset_state()

    def flush_dns(self):
        resolvers = [
            (["systemd-resolve", "--flush-caches"], "systemd-resolved"),
            (["resolvectl", "flush-caches"],         "resolvectl"),
            (["sudo", "killall", "-HUP", "dnsmasq"], "dnsmasq"),
            (["sudo", "nscd", "-i", "hosts"],        "nscd"),
            (["sudo", "rndc", "flush"],              "BIND/named"),
        ]
        flushed = False
        for cmd, name in resolvers:
            try:
                res = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, timeout=5)
                if res.returncode == 0:
                    self._log(f"{_ts()} [ENGINE] DNS cache flushed via {name}")
                    flushed = True
                    break
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        if not flushed:
            self._log(f"{_ts()} [ENGINE] DNS flush: no active caching resolver found")

    def is_running(self):
        return not self.stop_event.is_set()

    def active_modules(self):
        return [n for n, t in self.threads.items() if t.is_alive()]


def _ts():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def main():
    """CLI entry point: run all modules until Ctrl+C."""
    engine = NIDSEngine()

    def _shutdown(sig, frame):
        engine.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    engine.start()

    while engine.is_running():
        time.sleep(1)


if __name__ == "__main__":
    main()
