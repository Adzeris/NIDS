#!/usr/bin/env python3
"""Append attacker MAC to macfilter.detected_macs (shared by detectors)."""

import threading

from config import load_config, save_config
from modules.firewall import ts

_lock = threading.Lock()


def persist(mac, last_ip="?", log_cb=None):
    """Save MAC for GUI review. last_ip may be attacker IP or \"?\" if unknown."""
    mac = mac.strip().upper()
    with _lock:
        try:
            cfg = load_config()
            mcfg = cfg.get("macfilter", {})
            blocked = {m.upper() for m in mcfg.get("blocked_macs", [])}
            allowed = {m.upper() for m in mcfg.get("allowed_macs", [])}
            # Already policy-decided: do not re-add to pending review.
            if mac in blocked or mac in allowed:
                return
            detected = mcfg.get("detected_macs", [])
            existing = {
                e["mac"].upper() for e in detected if isinstance(e, dict) and "mac" in e
            }
            if mac in existing:
                return
            ip = last_ip if (last_ip and str(last_ip).strip()) else "?"
            detected.append({"mac": mac, "last_ip": ip, "first_seen": ts()})
            cfg["macfilter"]["detected_macs"] = detected
            save_config(cfg)
            if log_cb:
                log_cb(f"[INFO] MAC {mac} ({ip}) added to detected list for review")
        except Exception as e:
            if log_cb:
                log_cb(f"[WARN] Could not persist detected MAC: {e}")
