#!/usr/bin/env python3
"""
Experiment scenario definitions.

A Scenario is a declarative description of:
  - which modules to enable and with what parameters
  - which detection method to use (baseline / improved)
  - expected attack profile (for ground-truth generation)
  - duration and repetition count
"""

import copy
import time


class GroundTruthLabel:
    """One labelled interval for evaluation."""

    def __init__(self, source_ip: str, detector: str, is_attack: bool,
                 start: float = 0.0, end: float = 0.0):
        self.source_ip = source_ip
        self.detector = detector
        self.is_attack = is_attack
        self.start = start
        self.end = end

    def to_dict(self):
        return {
            'source_ip': self.source_ip,
            'detector': self.detector,
            'is_attack': self.is_attack,
            'start': self.start,
            'end': self.end,
        }


class Scenario:
    """Declarative experiment scenario."""

    def __init__(self, name: str, description: str, *,
                 modules: dict | None = None,
                 method: str = 'improved',
                 detect_only: bool = True,
                 duration_sec: int = 60,
                 repetitions: int = 1,
                 config_overrides: dict | None = None,
                 ground_truth: list | None = None):
        self.name = name
        self.description = description
        self.modules = modules or {
            'portscan': True, 'bruteforce': True,
            'dos': True, 'spoof': True, 'macfilter': False,
        }
        self.method = method
        self.detect_only = detect_only
        self.duration_sec = duration_sec
        self.repetitions = repetitions
        self.config_overrides = config_overrides or {}
        self.ground_truth = ground_truth or []

    def apply_to_config(self, base_cfg: dict) -> dict:
        """Return a new config dict with this scenario's settings applied."""
        cfg = copy.deepcopy(base_cfg)
        cfg['modules'] = self.modules
        cfg.setdefault('research', {})
        cfg['research']['method'] = self.method
        cfg['research']['detect_only'] = self.detect_only

        for section, overrides in self.config_overrides.items():
            if section in cfg and isinstance(cfg[section], dict):
                cfg[section].update(overrides)
            else:
                cfg[section] = overrides
        return cfg

    def to_dict(self):
        return {
            'name': self.name,
            'description': self.description,
            'modules': self.modules,
            'method': self.method,
            'detect_only': self.detect_only,
            'duration_sec': self.duration_sec,
            'repetitions': self.repetitions,
            'config_overrides': self.config_overrides,
            'ground_truth': [gt.to_dict() if hasattr(gt, 'to_dict') else gt
                             for gt in self.ground_truth],
        }


# ---------------------------------------------------------------------------
# Built-in scenario templates
# ---------------------------------------------------------------------------

PORTSCAN_BASELINE_VS_IMPROVED = Scenario(
    name='portscan_comparison',
    description='Compare baseline (threshold-only) vs improved (entropy-augmented) port scan detection',
    modules={'portscan': True, 'bruteforce': False, 'dos': False,
             'spoof': False, 'macfilter': False},
    duration_sec=120,
    repetitions=3,
)

DOS_CUSUM_VS_THRESHOLD = Scenario(
    name='dos_comparison',
    description='Compare baseline (pps threshold) vs improved (CUSUM) DoS detection',
    modules={'portscan': False, 'bruteforce': False, 'dos': True,
             'spoof': False, 'macfilter': False},
    duration_sec=120,
    repetitions=3,
)

SPOOF_ZSCORE_VS_DEVIATION = Scenario(
    name='spoof_comparison',
    description='Compare baseline (mode deviation) vs improved (Z-score) TTL spoof detection',
    modules={'portscan': False, 'bruteforce': False, 'dos': False,
             'spoof': True, 'macfilter': False},
    duration_sec=180,
    repetitions=3,
)

FULL_SYSTEM_EVALUATION = Scenario(
    name='full_system',
    description='All modules active for full-system evaluation',
    duration_sec=300,
    repetitions=5,
)
