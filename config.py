#!/usr/bin/env python3
"""
Unified configuration for the NIDS system.
All thresholds, interface settings, and module toggles live here.
"""

import json
import os

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nids_config.json")

DEFAULTS = {
    "interface": "eth0",

    "modules": {
        "portscan": True,
        "bruteforce": True,
        "dos": True,
        "spoof": True,
        "macfilter": True,
    },

    "portscan": {
        "window_sec": 5,
        "port_threshold": 10,
        "syn_threshold": 15,
        "block_seconds": 120,
    },

    "bruteforce": {
        "threshold": 5,
        "window_sec": 60,
        "block_seconds": 120,
    },

    "dos": {
        "threshold_pps": 500,
        "block_seconds": 60,
    },

    "spoof": {
        "arp_watch": True,
        "whitelist_host": False,
        "host_ip": "",
        "arp_alert_cooldown": 60,
        "ttl_deviation": 20,
        "ttl_min_samples": 20,
        "block_seconds": 120,
        "whitelist_ips": [],
    },

    "macfilter": {
        "mode": "whitelist",
        "allowed_macs": [],
        "blocked_macs": [],
        "detected_macs": [],
    },

    "logging": {
        "log_dir": os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs"),
        "log_to_file": True,
    },
}


def load_config():
    """Load config from JSON file, falling back to defaults for missing keys."""
    cfg = _deep_copy(DEFAULTS)
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r") as f:
            user = json.load(f)
        _deep_merge(cfg, user)
    return cfg


def save_config(cfg):
    """Persist current config to JSON."""
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)


def _deep_copy(d):
    return json.loads(json.dumps(d))


def _deep_merge(base, override):
    for k, v in override.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
