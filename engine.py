#!/usr/bin/env python3
"""
Unified NIDS engine.
Runs all enabled detection modules in parallel threads, with a shared
stop_event for clean shutdown.
"""

import threading
import signal
import subprocess
import sys
import os
import time
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import load_config
from modules import bruteforce, dos, portscan, spoof, macfilter
from modules.firewall import destroy_chain

DETECTORS = {
    "portscan": portscan,
    "bruteforce": bruteforce,
    "dos": dos,
    "spoof": spoof,
    "macfilter": macfilter,
}


class NIDSEngine:
    """
    Central engine that manages detector threads and funnels their
    log output through a single callback.
    """

    def __init__(self, cfg=None, log_callback=None):
        self.cfg = cfg or load_config()
        self.log_callback = log_callback or self._default_log
        self.stop_event = threading.Event()
        self._shutdown_complete = False
        self.threads = {}
        self._lock = threading.Lock()
        self._log_lines = []

        log_dir = self.cfg["logging"]["log_dir"]
        os.makedirs(log_dir, exist_ok=True)
        self._log_file = None
        if self.cfg["logging"]["log_to_file"]:
            path = os.path.join(log_dir, f"nids_{time.strftime('%Y%m%d_%H%M%S')}.log")
            self._log_file = open(path, "a")

    def _default_log(self, msg):
        print(msg, flush=True)

    def _log(self, msg):
        with self._lock:
            if self._shutdown_complete:
                return
            self._log_lines.append(msg)
            if self._log_file:
                try:
                    self._log_file.write(msg + "\n")
                    self._log_file.flush()
                except (ValueError, OSError):
                    pass
        try:
            self.log_callback(msg)
        except (RuntimeError, OSError):
            pass

    def get_log_lines(self):
        with self._lock:
            return list(self._log_lines)

    def start(self):
        """Start all enabled modules in background threads."""
        enabled = self.cfg["modules"]

        for stale in ["NIDS_BLOCK"]:
            destroy_chain(stale)

        self._log(f"{_ts()} [ENGINE] Starting NIDS — interface: {self.cfg['interface']}")

        for name, mod in DETECTORS.items():
            if not enabled.get(name, False):
                self._log(f"{_ts()} [ENGINE] {name} is disabled, skipping")
                continue

            mod.set_callback(self._log)
            t = threading.Thread(
                target=self._run_module,
                args=(name, mod),
                daemon=True,
                name=f"nids-{name}",
            )
            t.start()
            self.threads[name] = t

        self._log(f"{_ts()} [ENGINE] All modules launched ({len(self.threads)} active)")

    def _run_module(self, name, mod):
        try:
            mod.run_detector(self.cfg, self.stop_event)
        except Exception as e:
            self._log(f"{_ts()} [ERROR] {name} crashed: {e}")

    def stop(self):
        """Signal all modules to stop and wait for threads to finish."""
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
            if self._log_file:
                try:
                    self._log_file.close()
                except (ValueError, OSError):
                    pass
                self._log_file = None

    def flush_dns(self):
        """Flush system DNS cache. Tries all known Linux resolvers."""
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
