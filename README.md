# NIDS — Network Intrusion Detection Research Platform (v4.0)

A modular, Python-based Network Intrusion Detection System designed as a **research platform** for evaluating and comparing detection algorithms under controlled, reproducible conditions.

## Research Motivation

Most lightweight NIDS implementations use fixed thresholds that are tuned by hand and never rigorously evaluated.  This project provides a framework for asking — and answering — whether statistically principled detection methods (entropy analysis, CUSUM change-point detection, Z-score anomaly modeling, inter-arrival time analysis) improve detection accuracy over simple thresholds, and by how much.

Every detector supports **baseline** (original threshold logic) and **improved** (enhanced algorithm) modes that can be compared head-to-head under identical traffic conditions.

## Detection Modules (v2.0)

| Module | Baseline | Improved | Key Research Signal |
|--------|----------|----------|---------------------|
| **Port Scan** | Threshold on unique ports + SYN count | + Shannon entropy of port distribution | Entropy distinguishes scanning (uniform) from normal traffic (clustered) |
| **Brute Force** | Failure count in window | + Inter-arrival time analysis | Low IAT variance = automated tool signature |
| **DoS / Flood** | ICMP pps threshold | + CUSUM change-point detection | Catches gradual ramp-up attacks missed by static thresholds |
| **IP Spoof** | TTL mode-deviation check | + Z-score statistical model | Principled anomaly detection with per-source distribution tracking |
| **MAC Filter** | Whitelist/blacklist policy | + structured feature context | Policy enforcement with research instrumentation |

Scan types detected: TCP SYN, Xmas, Null, FIN, ACK (stealth), UDP probes — with fast and slow detection windows.

## Research Features

- **Baseline vs improved comparison**: every detector supports mode switching via config
- **Detect-only mode**: suppresses blocking for clean evaluation
- **Per-alert feature vectors**: each alert carries the features that triggered it
- **Confidence scoring**: weighted multi-signal confidence on every detection event
- **Structured JSONL logging**: machine-readable event stream with research metadata
- **Run traceability**: every run gets a unique ID, config hash, and git commit stamp
- **Evaluation framework**: confusion matrix, precision/recall/F1, detection latency
- **Experiment runner**: reproducible scenario execution with result storage
- **Ground-truth labeling**: structured format for attack/benign interval labeling

## Architecture

```
NIDS 4.0.desktop         Double-click to launch the app (runs nids.sh). Run installer once
                           so paths/icons are correct (see installer/ below).
installer/
  install.sh               Full installer (venv, pip, menu shortcut, rewrites launchers)
  Install NIDS.desktop     Double-click runs install.sh next to it

engine.py                  Central orchestrator — starts detector threads, collects events
config.py                  Unified configuration with schema versioning
gui.py                     PyQt5 desktop interface

modules/
  base.py                  BaseDetector class + statistical utilities (entropy, Z-score, CUSUM, IAT)
  portscan.py              PortScanDetector  — entropy-augmented multi-strategy
  bruteforce.py            BruteForceDetector — IAT temporal-pattern analysis
  dos.py                   DoSDetector — CUSUM change-point detection
  spoof.py                 SpoofDetector — Z-score TTL + multi-signal confidence
  macfilter.py             MACFilterDetector — policy enforcement
  firewall.py              Shared iptables helpers
  netutil.py               Network utility functions
  arpnft.py                nftables ARP/L2 drop
  detected_mac_persist.py  MAC persistence for GUI review

research/                  Lab tooling (optional — not required for normal NIDS use)
  metrics.py               ConfusionMatrix, precision/recall/F1, detection latency
  analyzer.py              Post-run analysis and comparison report generation
  scenarios.py             Scenario definitions and built-in templates
  runner.py                Experiment execution with reproducible result storage

(results/ is created automatically when you use research/runner.py — gitignored)
```

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run with GUI (needs root for packet capture)
sudo python3 gui.py

# Or run headless
sudo python3 engine.py

# Or double-click **NIDS 4.0.desktop** after ./installer/install.sh once (see Desktop launchers below)
```

### Desktop launchers

| File | Purpose |
|------|---------|
| **`NIDS 4.0.desktop`** (repo root) | Double‑click to **start NIDS** (`nids.sh`). |
| **`installer/Install NIDS.desktop`** | Double‑click to **run the installer** (venv + menu shortcut). |

**Why the icon might be missing:** `.desktop` files do not load `Icon=icons/nids.png` as a path to a file — that string is treated as an *icon theme* name. This project uses **`icons/nids.png`** as a real file, so the installer writes **`Icon=/full/path/to/icons/nids.png`** and also copies the PNG into your user icon theme as **`nids`**.

**One-time setup** (venv + correct icon + rewritten `NIDS 4.0.desktop`):

```bash
chmod +x installer/install.sh nids.sh
./installer/install.sh
```

On **GNOME**, if double‑click does nothing, right‑click the `.desktop` → **Allow launching**.

**Run NIDS manually:** `./nids.sh`  
**Install manually:** `./installer/install.sh` (or double-click `installer/Install NIDS.desktop`)

## Running an Experiment

```python
from research.scenarios import PORTSCAN_BASELINE_VS_IMPROVED
from research.runner import run_experiment

# Run baseline
scenario = PORTSCAN_BASELINE_VS_IMPROVED
scenario.method = 'baseline'
run_experiment(scenario)

# Run improved
scenario.method = 'improved'
run_experiment(scenario)
```

Results are stored in `results/<scenario_name>/<run_id>/` with:
- `config_snapshot.json` — exact config used
- `events.jsonl` — all structured detection events
- `metadata.json` — run ID, timestamps, config hash, git commit

## Analysing Results

```python
from research.analyzer import analyze_run
report = analyze_run('results/.../events.jsonl', 'ground_truth.json')
```

## Configuration

All settings live in `nids_config.json`.  Key research settings:

```json
{
  "research": {
    "detect_only": false,
    "method": "improved"
  }
}
```

- `detect_only`: when `true`, alerts are emitted but no iptables blocking occurs
- `method`: `"baseline"` for original threshold logic, `"improved"` for enhanced algorithms

## Requirements

- Python 3.10+, PyQt5, Scapy
- Linux with iptables (root privileges required for packet capture)
- Optional: nftables for L2 ARP drop

## Author

MD Saadman Kabir — ID: 25502701
