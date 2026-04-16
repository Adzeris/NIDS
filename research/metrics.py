#!/usr/bin/env python3
"""
Evaluation metrics for NIDS detection experiments.

Provides:
  ConfusionMatrix  — accumulator for TP/FP/TN/FN with derived metrics
  compare_methods  — side-by-side baseline vs improved analysis
  detection_latency — time from attack onset to first matching alert (optional IP/window)
"""

from __future__ import annotations
import json
import os
import time


class ConfusionMatrix:
    """Accumulates true/false positive/negative counts and derives metrics."""

    def __init__(self, label: str = ''):
        self.label = label
        self.tp = 0
        self.fp = 0
        self.tn = 0
        self.fn = 0

    def record(self, predicted: bool, actual: bool):
        if predicted and actual:
            self.tp += 1
        elif predicted and not actual:
            self.fp += 1
        elif not predicted and actual:
            self.fn += 1
        else:
            self.tn += 1

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        total = self.tp + self.fp + self.tn + self.fn
        return (self.tp + self.tn) / total if total > 0 else 0.0

    @property
    def false_positive_rate(self) -> float:
        denom = self.fp + self.tn
        return self.fp / denom if denom > 0 else 0.0

    def to_dict(self) -> dict:
        return {
            'label': self.label,
            'tp': self.tp, 'fp': self.fp, 'tn': self.tn, 'fn': self.fn,
            'precision': round(self.precision, 4),
            'recall': round(self.recall, 4),
            'f1': round(self.f1, 4),
            'accuracy': round(self.accuracy, 4),
            'fpr': round(self.false_positive_rate, 4),
        }

    def __repr__(self):
        return (f"CM({self.label}: TP={self.tp} FP={self.fp} "
                f"TN={self.tn} FN={self.fn} "
                f"P={self.precision:.3f} R={self.recall:.3f} F1={self.f1:.3f})")


def detection_latency(
    attack_start_ts: float,
    events: list[dict],
    *,
    source_ip: str | None = None,
    attack_end_ts: float | None = None,
) -> float | None:
    """Seconds from attack_start_ts to the first matching ALERT after that time.

    If *source_ip* is set, only alerts for that IP count.  If *attack_end_ts*
    is set, only alerts with timestamp <= *attack_end_ts* count.  Returns None
    if no matching alert exists."""
    for ev in sorted(events, key=lambda e: e.get('timestamp', 0)):
        if ev.get('event_type') != 'ALERT':
            continue
        ts = ev.get('timestamp')
        if ts is None:
            continue
        if ts < attack_start_ts:
            continue
        if attack_end_ts is not None and ts > attack_end_ts:
            continue
        if source_ip is not None and ev.get('source_ip') != source_ip:
            continue
        return ts - attack_start_ts
    return None


def compare_methods(baseline_events: list[dict], improved_events: list[dict],
                    ground_truth: list[dict]) -> dict:
    """Compare baseline vs improved using shared ground-truth labels.

    ground_truth entries: {'timestamp': float, 'source_ip': str, 'is_attack': bool}
    Returns dict with per-method ConfusionMatrix summaries.
    """
    def _build_alert_set(events):
        return {ev['source_ip'] for ev in events
                if ev.get('event_type') == 'ALERT' and ev.get('source_ip')}

    baseline_alerts = _build_alert_set(baseline_events)
    improved_alerts = _build_alert_set(improved_events)

    cm_base = ConfusionMatrix('baseline')
    cm_impr = ConfusionMatrix('improved')

    for gt in ground_truth:
        ip = gt['source_ip']
        is_attack = gt['is_attack']
        cm_base.record(ip in baseline_alerts, is_attack)
        cm_impr.record(ip in improved_alerts, is_attack)

    return {
        'baseline': cm_base.to_dict(),
        'improved': cm_impr.to_dict(),
    }


def save_metrics(metrics: dict, path: str):
    """Persist metrics dict as JSON."""
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    with open(path, 'w') as f:
        json.dump(metrics, f, indent=2, default=str)


def load_events(jsonl_path: str) -> list[dict]:
    """Load structured events from a JSONL log file."""
    events = []
    with open(jsonl_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events
