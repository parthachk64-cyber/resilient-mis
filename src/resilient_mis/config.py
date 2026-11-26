"""Configuration: embedded defaults, optionally overridden by a YAML file. Every number here is a declared choice."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml

DEFAULTS: dict[str, Any] = {
    "rsa_bits": 3072,
    "tenants": ["tenant-a", "tenant-b"],
    "service": {"session_ttl_s": 3600},
    "detection": {
        "window_s": 300,                  # rolling window for per-principal features
        "alert_merge_s": 600,             # alerts of one principal closer than this merge into one alert group
        "match_grace_s": 600,             # an alert group may start up to this long after an incident's end and still match it
        "rules": {"deny_per_window": 5, "export_per_window": 10, "requests_per_window": 60, "tenant_hops": 2},
        "iforest": {"n_estimators": 200, "max_samples": 256},
        "threshold_policy": "match the rule baseline's development false-alert rate (dev non-incident events only)",
    },
    "workload": {"days_train": 12, "days_dev": 6, "days_test": 12, "managers_per_tenant": 3, "analysts_per_tenant": 6,
                 "incidents_dev": 4, "incidents_test": 12, "burst_days_dev": [3], "burst_days_test": [10, 11]},
    "probes": {"cadence_s": 0.25, "deadline_s": 1.0, "observation_s": 9.0, "fault_at_s": 2.0},
    "benchmark": {"detection_trials": 10, "recovery_trials": 10, "latency_reps": 200, "snapshot_reps": 20, "orders_per_department": 12},
}


def _merge(base: dict[str, Any], over: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    if path is None:
        return copy.deepcopy(DEFAULTS)
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("config file must contain a mapping")
    return _merge(DEFAULTS, data)
