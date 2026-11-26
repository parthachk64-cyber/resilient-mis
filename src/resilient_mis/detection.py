"""Continuous anomaly detection over telemetry in replay (arrival) order.

Features for an event use ONLY events that had already arrived (arrival <= now) in a rolling per-principal window. Labels,
scenario names and incident ids never enter the matrix (``assert_features_safe``). Two detectors score the same matrix:

* ``RuleDetector``: interpretable fixed thresholds, each rule reports which limit was crossed.
* ``IsolationDetector``: seeded Isolation Forest fitted on EARLIER NORMAL activity only.
Access denials are an input signal, not alerts; an alert is a detector decision; labels are evaluation-only.
"""

from __future__ import annotations

import math
from collections import deque
from collections.abc import Iterable
from datetime import datetime
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURES = ("n_req", "n_deny", "deny_frac", "n_export", "n_read", "n_report", "n_write", "n_tenants", "n_denied_tenants",
            "hour_sin", "hour_cos", "off_hours", "log_gap_s")
_BANNED = ("label", "incident", "scenario", "kind", "truth", "attack", "anomal")
_WRITE = {"create_order", "update_order"}


def assert_features_safe(names: Iterable[str]) -> None:
    bad = [n for n in names if any(b in n.lower() for b in _BANNED)]
    if bad:
        raise ValueError(f"feature names look like labels or annotations: {bad}")


assert_features_safe(FEATURES)


class FeatureBuilder:
    """Streaming features. ``push`` must be called in arrival order."""

    def __init__(self, window_s: float) -> None:
        self.window_s = window_s
        self._win: dict[str, deque[tuple[float, str, str, str]]] = {}
        self._last: dict[str, float] = {}

    def push(self, principal: str, tenant: str, operation: str, decision: str, arrival: datetime, event_time: datetime) -> list[float]:
        now = arrival.timestamp()
        w = self._win.setdefault(principal, deque())
        w.append((now, operation, decision, tenant))
        while w and now - w[0][0] > self.window_s:
            w.popleft()
        n = len(w)
        deny = sum(1 for x in w if x[2] == "deny")
        hour = event_time.hour + event_time.minute / 60.0
        gap = now - self._last.get(principal, now - 86400.0)
        self._last[principal] = now
        return [float(n), float(deny), deny / n, float(sum(1 for x in w if x[1] == "export_report")),
                float(sum(1 for x in w if x[1] == "read_order")), float(sum(1 for x in w if x[1] == "spending_report")),
                float(sum(1 for x in w if x[1] in _WRITE)), float(len({x[3] for x in w})),
                float(len({x[3] for x in w if x[2] == "deny"})), math.sin(2 * math.pi * hour / 24), math.cos(2 * math.pi * hour / 24),
                1.0 if (hour < 7 or hour >= 20) else 0.0, math.log1p(min(max(gap, 0.0), 86400.0))]


def build_matrix(events: list[dict[str, Any]], window_s: float) -> np.ndarray:
    """``events`` as returned by ``telemetry.load_events`` (already in arrival order)."""
    fb = FeatureBuilder(window_s)
    return np.array([fb.push(e["principal"], e["tenant"], e["operation"], e["decision"], e["_arrival_dt"], e["_event_dt"]) for e in events],
                    dtype=float).reshape(len(events), len(FEATURES))


class RuleDetector:
    name = "rules"

    def __init__(self, rules: dict[str, float]) -> None:
        self.r = rules

    def score(self, X: np.ndarray) -> np.ndarray:
        i = {n: k for k, n in enumerate(FEATURES)}
        parts = np.stack([X[:, i["n_deny"]] / self.r["deny_per_window"], X[:, i["n_export"]] / self.r["export_per_window"],
                          X[:, i["n_req"]] / self.r["requests_per_window"], X[:, i["n_denied_tenants"]] / self.r["tenant_hops"]], axis=1)
        return parts.max(axis=1)

    def alerts(self, X: np.ndarray) -> np.ndarray:
        return self.score(X) >= 1.0

    def reasons(self, x: np.ndarray) -> list[str]:
        i = {n: k for k, n in enumerate(FEATURES)}
        out = []
        for rule, feat in (("deny_per_window", "n_deny"), ("export_per_window", "n_export"), ("requests_per_window", "n_req"),
                           ("tenant_hops", "n_denied_tenants")):
            if x[i[feat]] >= self.r[rule]:
                out.append(f"{feat}={x[i[feat]]:g} >= {self.r[rule]:g}")
        return out


class IsolationDetector:
    name = "iforest"

    def __init__(self, seed: int, n_estimators: int = 200, max_samples: int = 256) -> None:
        self.scaler = StandardScaler()
        self.model = IsolationForest(n_estimators=n_estimators, max_samples=max_samples, random_state=seed)

    def fit(self, X_normal: np.ndarray) -> IsolationDetector:
        if len(X_normal) < 10:
            raise ValueError("too little normal activity to fit a detector")
        self.model.fit(self.scaler.fit_transform(X_normal))
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        return -self.model.score_samples(self.scaler.transform(X))


def select_threshold(dev_scores: np.ndarray, dev_is_incident_event: np.ndarray, target_rate: float) -> float:
    """Choose the score threshold on DEVELOPMENT data so the alert rate on non-incident events equals ``target_rate``."""
    normal = np.sort(dev_scores[~dev_is_incident_event])
    if len(normal) == 0:
        raise ValueError("development data has no normal events to calibrate on")
    rate = max(target_rate, 1.0 / len(normal))
    k = min(len(normal) - 1, int(math.ceil(len(normal) * (1 - rate))))
    return float(normal[k])
