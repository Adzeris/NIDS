#!/usr/bin/env python3
"""
Experiment runner — executes scenarios and stores results reproducibly.

Each run produces:
  results/<scenario_name>/<run_id>/
    config_snapshot.json   — exact config used
    scenario.json          — scenario definition
    events.jsonl           — all detector events
    metadata.json          — run ID, timestamps, git commit, config hash
"""

import json
import os
import subprocess
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import load_config
from engine import NIDSEngine
from modules.base import config_hash


def _git_commit():
    try:
        return subprocess.check_output(
            ['git', 'rev-parse', '--short', 'HEAD'],
            stderr=subprocess.DEVNULL, text=True,
        ).strip()
    except Exception:
        return 'unknown'


def run_experiment(scenario, base_cfg=None, results_root='results'):
    """Execute a single scenario and persist all artefacts.

    Args:
        scenario:     research.scenarios.Scenario instance
        base_cfg:     base config dict (loaded from nids_config.json if None)
        results_root: root directory for result artefacts

    Returns:
        dict with run metadata and collected events
    """
    base_cfg = base_cfg or load_config()
    cfg = scenario.apply_to_config(base_cfg)

    run_id = time.strftime('%Y%m%d_%H%M%S') + '_' + uuid.uuid4().hex[:6]
    run_dir = os.path.join(results_root, scenario.name, run_id)
    os.makedirs(run_dir, exist_ok=True)

    metadata = {
        'run_id': run_id,
        'scenario': scenario.name,
        'method': scenario.method,
        'detect_only': scenario.detect_only,
        'duration_sec': scenario.duration_sec,
        'config_hash': config_hash(cfg),
        'git_commit': _git_commit(),
        'start_time': None,
        'end_time': None,
    }

    with open(os.path.join(run_dir, 'config_snapshot.json'), 'w') as f:
        json.dump(cfg, f, indent=2, default=str)
    with open(os.path.join(run_dir, 'scenario.json'), 'w') as f:
        json.dump(scenario.to_dict(), f, indent=2, default=str)

    collected_logs = []

    def _log(msg):
        collected_logs.append(msg)
        print(msg, flush=True)

    engine = NIDSEngine(cfg=cfg, log_callback=_log)

    metadata['start_time'] = time.time()
    engine.start()

    try:
        deadline = time.time() + scenario.duration_sec
        while time.time() < deadline and engine.is_running():
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        engine.stop()
        metadata['end_time'] = time.time()

    events = engine.get_detector_events()

    events_path = os.path.join(run_dir, 'events.jsonl')
    with open(events_path, 'w') as f:
        for ev in events:
            f.write(json.dumps(ev, default=str) + '\n')

    with open(os.path.join(run_dir, 'metadata.json'), 'w') as f:
        json.dump(metadata, f, indent=2, default=str)

    if scenario.ground_truth:
        gt = [gt.to_dict() if hasattr(gt, 'to_dict') else gt
              for gt in scenario.ground_truth]
        with open(os.path.join(run_dir, 'ground_truth.json'), 'w') as f:
            json.dump(gt, f, indent=2, default=str)

    print(f"\n[EXPERIMENT] Run complete: {run_dir}")
    print(f"  Events: {len(events)}  Duration: {metadata['end_time'] - metadata['start_time']:.1f}s")

    return {
        'run_id': run_id,
        'run_dir': run_dir,
        'metadata': metadata,
        'events': events,
    }


def run_repeated(scenario, repetitions=None, base_cfg=None,
                 results_root='results'):
    """Run a scenario multiple times and collect all results."""
    reps = repetitions or scenario.repetitions
    results = []
    for i in range(reps):
        print(f"\n{'='*60}")
        print(f"  Repetition {i+1}/{reps} — {scenario.name}")
        print(f"{'='*60}")
        result = run_experiment(scenario, base_cfg, results_root)
        results.append(result)
    return results


if __name__ == '__main__':
    from research.scenarios import FULL_SYSTEM_EVALUATION
    run_experiment(FULL_SYSTEM_EVALUATION)
