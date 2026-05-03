#!/usr/bin/env python3
"""
Base detector interface for the NIDS research platform (v5.0).

Provides:
  - BaseDetector: abstract base class with structured event emission,
    confidence scoring, adaptive signal scoring, and detect-only mode
  - DetectionEvent: structured event with feature vector and research metadata
  - Statistical utilities: Shannon entropy, Z-score, rolling statistics,
    inter-arrival times, CUSUM change-point detection
"""

import time
import math
import threading
import hashlib
import json


class DetectionEvent:
    """A single detection event carrying full research metadata."""

    __slots__ = (
        'timestamp', 'detector', 'detector_version', 'method',
        'event_type', 'source_ip', 'source_mac', 'target_ip',
        'confidence', 'features', 'message', 'action_taken',
    )

    def __init__(self, detector, detector_version, method, event_type,
                 message, source_ip=None, source_mac=None, target_ip=None,
                 confidence=0.0, features=None, action_taken='alert'):
        self.timestamp = time.time()
        self.detector = detector
        self.detector_version = detector_version
        self.method = method
        self.event_type = event_type
        self.source_ip = source_ip
        self.source_mac = source_mac
        self.target_ip = target_ip
        self.confidence = confidence
        self.features = features or {}
        self.message = message
        self.action_taken = action_taken

    def to_dict(self):
        return {
            'timestamp': self.timestamp,
            'timestamp_iso': time.strftime(
                '%Y-%m-%dT%H:%M:%S', time.localtime(self.timestamp)),
            'detector': self.detector,
            'detector_version': self.detector_version,
            'method': self.method,
            'event_type': self.event_type,
            'source_ip': self.source_ip,
            'source_mac': self.source_mac,
            'target_ip': self.target_ip,
            'confidence': round(self.confidence, 4),
            'features': self.features,
            'message': self.message,
            'action_taken': self.action_taken,
        }


class BaseDetector:
    """
    Abstract base for all detection modules.

    Subclasses must set NAME, VERSION, CHAIN and implement run().
    Detection behaviour is controlled by two research settings:
      detect_only  – if True, alerts are emitted but blocking is suppressed
      method       – logical algorithm profile tag for event metadata
    """

    NAME = 'base'
    VERSION = '0.0'
    CHAIN = 'NIDS_BASE'

    def __init__(self, cfg, stop_event, log_callback=None):
        self.cfg = cfg
        self.stop_event = stop_event or threading.Event()
        self._log_cb = log_callback or (lambda msg: print(msg, flush=True))
        self.stats = {}
        self._events = []
        self._ev_lock = threading.Lock()

        research = cfg.get('research', {})
        self.detect_only = research.get('detect_only', False)
        # Runtime detection behavior uses one adaptive profile only.
        self.method = 'adaptive'

    # -- Logging -----------------------------------------------------------

    def _ts(self):
        return time.strftime('%Y-%m-%d %H:%M:%S')

    def _emit(self, msg):
        line = f"{self._ts()} {msg}"
        try:
            self._log_cb(line)
        except (RuntimeError, OSError):
            pass

    # -- Structured event recording ----------------------------------------

    def _record(self, event):
        with self._ev_lock:
            self._events.append(event)

    def alert(self, message, *, source_ip=None, source_mac=None,
              target_ip=None, confidence=0.0, features=None):
        ev = DetectionEvent(
            detector=self.NAME, detector_version=self.VERSION,
            method=self.method, event_type='ALERT', message=message,
            source_ip=source_ip, source_mac=source_mac,
            target_ip=target_ip, confidence=confidence,
            features=features, action_taken='alert',
        )
        self._record(ev)
        conf_str = f" [conf={confidence:.2f}]" if confidence > 0 else ""
        self._emit(f"[ALERT]{conf_str} {message}")
        return ev

    def block(self, target, reason, *, source_ip=None, source_mac=None,
              confidence=0.0, features=None, do_block_fn=None):
        """Record a block decision.  Execute do_block_fn only when not in
        detect-only mode."""
        actually_blocked = False
        if not self.detect_only and do_block_fn:
            do_block_fn()
            actually_blocked = True

        action = 'block' if actually_blocked else 'detect_only'
        label = 'Blocked' if actually_blocked else 'Would block'
        ev = DetectionEvent(
            detector=self.NAME, detector_version=self.VERSION,
            method=self.method, event_type='BLOCK',
            message=f"{label} {target} ({reason})",
            source_ip=source_ip, source_mac=source_mac,
            confidence=confidence, features=features,
            action_taken=action,
        )
        self._record(ev)
        tag = "BLOCK" if actually_blocked else "DETECT"
        self._emit(f"[{tag}] {label} {target}")
        return actually_blocked

    def info(self, message):
        self._emit(f"[INFO] {message}")

    def warn(self, message):
        self._emit(f"[WARN] {message}")

    # -- Event access ------------------------------------------------------

    def get_events(self):
        with self._ev_lock:
            return [e.to_dict() for e in self._events]

    def clear_events(self):
        with self._ev_lock:
            self._events.clear()

    # -- Subclass contract -------------------------------------------------

    def run(self):
        raise NotImplementedError

    def reset_state(self):
        """Clear runtime tracking state.  Override in subclass."""
        pass


# ---------------------------------------------------------------------------
# Statistical utilities used by detection algorithms
# ---------------------------------------------------------------------------

def shannon_entropy(counts):
    """Compute Shannon entropy from a ``{value: count}`` mapping.

    In this project the function is used mainly for destination-port
    distributions. A high value suggests traffic spread across many ports,
    which is a useful scan signal; a low value suggests concentration on a
    small set of services, which is more typical of ordinary client behavior.
    """
    total = sum(counts.values())
    if total <= 0:
        return 0.0
    h = 0.0
    for c in counts.values():
        if c > 0:
            p = c / total
            h -= p * math.log2(p)
    return h


def z_score(value, mean, std):
    """Return the absolute Z-score of ``value`` relative to ``mean``/``std``.

    The helper returns ``0.0`` when ``std`` is zero so detector code can treat
    "no observed variation yet" as "no statistical anomaly yet" instead of
    failing on division by zero.
    """
    return abs(value - mean) / std if std > 0 else 0.0


def rolling_stats(values):
    """Return ``(mean, std)`` for a numeric sample sequence.

    The standard deviation uses Bessel's correction (``n - 1``) because the
    tracked values are empirical samples rather than a full population.
    """
    n = len(values)
    if n == 0:
        return 0.0, 0.0
    mean = sum(values) / n
    if n < 2:
        return mean, 0.0
    var = sum((x - mean) ** 2 for x in values) / (n - 1)
    return mean, math.sqrt(var)


def inter_arrival_times(timestamps):
    """Convert event timestamps into inter-arrival deltas.

    Inter-arrival times are useful for spotting automation: repeated actions
    that arrive with very regular spacing tend to indicate scripted tools
    rather than organic human behavior.
    """
    if len(timestamps) < 2:
        return []
    return [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]


def cusum_step(prev_sum, observation, expected, slack):
    """Advance the one-sided CUSUM statistic by one observation.

    ``expected`` is the learned baseline rate and ``slack`` is the tolerated
    deviation before the running sum starts to grow. Clamping at zero keeps the
    statistic focused on sustained positive drift instead of isolated spikes.
    """
    return max(0.0, prev_sum + (observation - expected - slack))


def config_hash(cfg):
    """Deterministic short hash of a config dict for run traceability."""
    canonical = json.dumps(cfg, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()[:12]
