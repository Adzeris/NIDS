#!/usr/bin/env python3
"""
Unified configuration for the NIDS research platform (v4.0).
All thresholds, interface settings, module toggles, and research
parameters live here.

Schema version is tracked for reproducibility — if the config layout
changes between versions, older snapshots can be identified.
"""

import json
import os

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nids_config.json")

CONFIG_SCHEMA_VERSION = "4.0"

DEFAULTS = {
    "schema_version": CONFIG_SCHEMA_VERSION,
    "interface": "auto",
    "network_mode": "nat",

    "modules": {
        "portscan": True,
        "bruteforce": True,
        "dos": True,
        "spoof": True,
        "macfilter": True,
    },

    "research": {
        "detect_only": False,
        "method": "adaptive",
    },

    "portscan": {
        "window_sec": 5,
        "port_threshold": 10,
        "syn_threshold": 15,
        "slow_window_sec": 120,
        "slow_port_threshold": 6,
        "slow_syn_threshold": 6,
        "udp_port_threshold": 8,
        "udp_probe_threshold": 12,
        "udp_window_sec": 10,
        "block_seconds": 120,
        # Throttle log spam for whitelisted (gateway) sources — same pattern can re-fire
        # every few seconds as state resets after each alert.
        "safe_ip_alert_cooldown_sec": 120,
        # Focus on LAN/private source IPs; ignore public internet background noise.
        "local_sources_only": True,
    },

    "bruteforce": {
        "threshold": 5,
        "window_sec": 60,
        "block_seconds": 120,
        "ftp_threshold": 5,
        "ftp_window_sec": 60,
    },

    "dos": {
        "threshold_pps": 500,
        "syn_threshold_pps": 120,
        "block_seconds": 60,
    },

    "spoof": {
        "whitelist_default_gateway": True,
        "arp_watch": True,
        "arp_burst_watch": True,
        "arp_burst_threshold": 12,
        "arp_burst_window_sec": 10,
        "arp_burst_cooldown": 30,
        "name_spoof_watch": True,
        "name_response_threshold": 8,
        "name_window_sec": 12,
        "name_query_grace_sec": 3,
        "name_conflict_window_sec": 20,
        "name_alert_cooldown": 60,
        "dhcp_watch": True,
        "dhcp_offer_threshold": 2,
        "dhcp_window_sec": 20,
        "dhcp_alert_cooldown": 60,
        "dns_spoof_watch": True,
        "dns_unsolicited_threshold": 5,
        "dns_window_sec": 20,
        "dns_query_grace_sec": 4,
        "dns_conflict_window_sec": 6,
        "dns_alert_cooldown": 60,
        "gateway_auto_whitelist": True,
        "whitelist_host": False,
        "host_ip": "",
        "arp_alert_cooldown": 60,
        "ttl_deviation": 20,
        "ttl_z_threshold": 2.5,
        "ttl_min_samples": 20,
        "ttl_alert_cooldown": 120,
        "ttl_max_alerts_per_source": 3,
        "ttl_local_only": True,
        "block_seconds": 120,
        "whitelist_ips": [],
        "trusted_name_servers": [],
        "trusted_dhcp_servers": [],
        "trusted_dhcp_macs": [],
        "trusted_dns_servers": [],
        "trusted_routers": [],
    },

    "macfilter": {
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
    cfg["schema_version"] = CONFIG_SCHEMA_VERSION
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
