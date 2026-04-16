#!/usr/bin/env python3
"""
Post-run analysis: load experiment results, match against ground truth,
compute per-detector metrics, and produce comparison reports.
"""

import json
import os
from collections import defaultdict

from research.metrics import (
    ConfusionMatrix, detection_latency, load_events, save_metrics,
)


def analyze_run(events_path: str, ground_truth_path: str,
                output_dir: str = 'results') -> dict:
    """Full analysis of a single experiment run.

    Args:
        events_path:       JSONL file with structured detection events
        ground_truth_path: JSON file with labelled rows (lab-authored)
        output_dir:        directory for result artefacts

    Ground truth format (each row is one labelled IP for that detector scope)::
        [
          {"source_ip": "10.0.0.5", "detector": "portscan",
           "is_attack": true, "start": 1700000000.0, "end": 1700000060.0},
          ...
        ]

    Classification uses **IP presence** (whether an alert occurred for that IP
    on the detector), not whether the alert fell inside ``start``/``end``.
    Optional ``start``/``end`` bound **latency** only: first ALERT for that IP
    at or after ``start`` (and at or before ``end`` if provided).
    """
    events = load_events(events_path)
    with open(ground_truth_path, 'r') as f:
        ground_truth = json.load(f)

    per_detector = defaultdict(list)
    for ev in events:
        per_detector[ev.get('detector', 'unknown')].append(ev)

    gt_by_detector = defaultdict(list)
    for gt in ground_truth:
        gt_by_detector[gt.get('detector', 'all')].append(gt)

    report = {
        'detectors': {},
        'evaluation_note': (
            'Exploratory metrics: IP-level match vs ground truth. '
            'Baseline vs improved normally requires two runs (one method each) '
            'unless events were merged from separate runs.'
        ),
    }

    for det_name, det_events in per_detector.items():
        gt_entries = gt_by_detector.get(det_name, gt_by_detector.get('all', []))
        cm = ConfusionMatrix(det_name)

        alert_ips = {ev['source_ip'] for ev in det_events
                     if ev.get('event_type') == 'ALERT' and ev.get('source_ip')}

        for gt in gt_entries:
            ip = gt['source_ip']
            cm.record(ip in alert_ips, gt['is_attack'])

        latencies = []
        for gt in gt_entries:
            if gt['is_attack']:
                end = gt.get('end')
                lat = detection_latency(
                    gt.get('start', 0),
                    det_events,
                    source_ip=gt.get('source_ip'),
                    attack_end_ts=end if end is not None else None,
                )
                if lat is not None:
                    latencies.append(lat)

        report['detectors'][det_name] = {
            'confusion_matrix': cm.to_dict(),
            'mean_latency_sec': (sum(latencies) / len(latencies)
                                 if latencies else None),
            'total_events': len(det_events),
            'alert_count': sum(1 for e in det_events
                               if e.get('event_type') == 'ALERT'),
            'block_count': sum(1 for e in det_events
                               if e.get('event_type') == 'BLOCK'),
        }

    # Rare: both methods in one file (e.g. merged JSONL). A normal run has one method.
    methods_seen = {ev.get('method') for ev in events}
    if 'baseline' in methods_seen and 'improved' in methods_seen:
        report['method_comparison'] = {
            'baseline_alerts': sum(
                1 for e in events
                if e.get('method') == 'baseline' and e.get('event_type') == 'ALERT'),
            'improved_alerts': sum(
                1 for e in events
                if e.get('method') == 'improved' and e.get('event_type') == 'ALERT'),
        }
        report['method_comparison_note'] = (
            'Counts both methods in this file; typical workflow uses one method per run.'
        )

    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, 'analysis_report.json')
    save_metrics(report, out_path)

    return report


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 3:
        print("Usage: python -m research.analyzer <events.jsonl> <ground_truth.json> [output_dir]")
        sys.exit(1)
    out = sys.argv[3] if len(sys.argv) > 3 else 'results'
    report = analyze_run(sys.argv[1], sys.argv[2], out)
    print(json.dumps(report, indent=2, default=str))
