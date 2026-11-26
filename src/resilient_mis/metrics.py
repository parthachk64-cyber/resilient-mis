"""Metric definitions. Pure functions so each can be checked against a hand calculation.

Zero denominators return ``None`` (reported as "undefined"), never 0 and never NaN.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any


def ratio(num: float, den: float) -> float | None:
    return None if den == 0 else num / den


def wilson(successes: int, n: int, z: float = 1.959964) -> tuple[float, float] | None:
    """95% Wilson score interval for a binomial proportion; None when n == 0."""
    if n == 0:
        return None
    p = successes / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, centre - half), min(1.0, centre + half)


def percentile(values: Sequence[float], q: float) -> float | None:
    """Linear-interpolation percentile (q in 0..100); None for an empty sample."""
    if not values:
        return None
    xs = sorted(values)
    if len(xs) == 1:
        return float(xs[0])
    pos = (len(xs) - 1) * q / 100.0
    lo, hi = math.floor(pos), math.ceil(pos)
    return float(xs[lo] + (xs[hi] - xs[lo]) * (pos - lo))


def prf(tp: int, fp: int, fn: int) -> dict[str, float | None]:
    p, r = ratio(tp, tp + fp), ratio(tp, tp + fn)
    f1 = None if p is None or r is None or (p + r) == 0 else 2 * p * r / (p + r)
    return {"precision": p, "recall": r, "f1": f1}


def alert_groups(alerts: list[tuple[str, datetime]], merge_s: float) -> list[dict[str, Any]]:
    """Merge alerts of the same principal that are closer than ``merge_s``. ``alerts`` = (principal, arrival time)."""
    by_p: dict[str, list[datetime]] = {}
    for p, t in alerts:
        by_p.setdefault(p, []).append(t)
    groups: list[dict[str, Any]] = []
    gap = timedelta(seconds=merge_s)
    for p, ts in by_p.items():
        ts.sort()
        start = prev = ts[0]
        n = 1
        for t in ts[1:]:
            if t - prev < gap:
                prev, n = t, n + 1
            else:
                groups.append({"principal": p, "start": start, "end": prev, "n_alerts": n})
                start = prev = t
                n = 1
        groups.append({"principal": p, "start": start, "end": prev, "n_alerts": n})
    return sorted(groups, key=lambda g: (g["start"], g["principal"]))


def incident_metrics(incidents: list[dict[str, Any]], groups: list[dict[str, Any]], grace_s: float, monitored_hours: float) -> dict[str, Any]:
    """Incident-level detection.

    * An incident is *eligible* if the caller passes it (the caller restricts to incidents wholly inside the evaluated window).
    * A group matches an incident when it has the same principal and starts in [onset, end + grace].
    * At most one true positive per incident; a group is attributed to the earliest incident it matches.
    * Groups inside an already-detected incident are ``duplicate_groups`` (neither TP nor false alert).
    * False alert groups match no incident. ``recall`` = detected / eligible, never overall accuracy.
    """
    grace = timedelta(seconds=grace_s)
    detected: dict[str, dict[str, Any]] = {}
    dup = fp = 0
    for g in groups:
        cands = [i for i in incidents if i["principal"] == g["principal"] and i["onset"] <= g["start"] <= i["end"] + grace]
        if not cands:
            fp += 1
            continue
        inc = min(cands, key=lambda i: i["onset"])
        if inc["incident_id"] in detected:
            dup += 1
        else:
            detected[inc["incident_id"]] = {"group_start": g["start"], "delay_s": (g["start"] - inc["onset"]).total_seconds()}
    tp = len(detected)
    n = len(incidents)
    missed = sorted(i["incident_id"] for i in incidents if i["incident_id"] not in detected)
    out: dict[str, Any] = {"eligible_incidents": n, "detected": tp, "missed": missed, "false_alert_groups": fp, "duplicate_groups": dup,
                           "groups": len(groups), "monitored_hours": monitored_hours,
                           "recall": ratio(tp, n), "recall_wilson95": wilson(tp, n), "precision": ratio(tp, tp + fp),
                           "false_alerts_per_hour": ratio(fp, monitored_hours), "detection_delays_s": sorted(d["delay_s"] for d in detected.values())}
    return out


def event_metrics(is_positive: Sequence[bool], is_alert: Sequence[bool]) -> dict[str, Any]:
    tp = sum(1 for p, a in zip(is_positive, is_alert) if p and a)
    fp = sum(1 for p, a in zip(is_positive, is_alert) if not p and a)
    fn = sum(1 for p, a in zip(is_positive, is_alert) if p and not a)
    tn = len(is_positive) - tp - fp - fn
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, **prf(tp, fp, fn)}


def availability(scheduled: int, records: list[dict[str, Any]], cadence_s: float) -> dict[str, Any]:
    """Business-probe availability. Scheduled probes with no record count as failures (``missing``)."""
    ok = sum(1 for r in records if r["ok"])
    missing = max(0, scheduled - len(records))
    return {"scheduled": scheduled, "recorded": len(records), "missing": missing, "successful": ok,
            "availability": ratio(ok, scheduled), "wilson95": wilson(ok, scheduled),
            "estimated_healthy_s": ok * cadence_s, "observed_s": scheduled * cadence_s}


def paired_overhead(baseline: Sequence[float], protected: Sequence[float]) -> dict[str, Any]:
    """Absolute (same unit as input) and relative change of p50 and p95. Relative denominator = baseline percentile."""
    out: dict[str, Any] = {"n_baseline": len(baseline), "n_protected": len(protected)}
    for q in (50, 95):
        b, p = percentile(baseline, q), percentile(protected, q)
        out[f"baseline_p{q}"], out[f"protected_p{q}"] = b, p
        out[f"abs_change_p{q}"] = None if b is None or p is None else p - b
        out[f"rel_change_p{q}"] = None if b is None or p is None else ratio(p - b, b)
    return out
