"""Synthetic telemetry workload and SEPARATE scenario annotations.

``generate`` returns ``events`` (schema identical to service telemetry) and ``labels`` (incident annotations). Labels carry the
incident kind and are only ever read by the evaluation code, never by feature construction. Everything here is invented:
no real traffic, people or organisations. Splits are chronological and whole incidents stay in one split.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import numpy as np

from resilient_mis.telemetry import iso

T0 = datetime(2026, 3, 2, tzinfo=timezone.utc)  # a Monday
KINDS = ("credential_stuffing", "bulk_export", "tenant_probe", "low_and_slow_export")


def _pid(seed: int, tenant: str, role: str, i: int) -> str:
    return "p-" + hashlib.sha1(f"{seed}|{tenant}|{role}|{i}".encode()).hexdigest()[:12]


def _normal_day(rng: np.random.Generator, pid: str, tenant: str, role: str, day: int, burst: bool) -> list[dict[str, Any]]:
    weekend = (day % 7) >= 5
    rate_h = (14.0 if role == "analyst" else 10.0) * (0.15 if weekend else 1.0)
    hours = (9.0, 17.0) if burst else (8.0, 18.0)
    mult = 4.0 if burst else 1.0
    n = int(rng.poisson(rate_h * (hours[1] - hours[0]) * mult))
    secs = np.sort(rng.uniform(hours[0] * 3600, hours[1] * 3600, n))
    if role == "analyst":
        ops, p = ["read_order", "spending_report"], [0.8, 0.2]
    elif burst:
        ops, p = ["read_order", "spending_report", "export_report", "update_order", "create_order"], [0.25, 0.5, 0.15, 0.05, 0.05]
    else:
        ops, p = ["read_order", "spending_report", "create_order", "update_order", "export_report"], [0.5, 0.25, 0.1, 0.1, 0.05]
    chosen = rng.choice(ops, size=n, p=p) if n else []
    denies = rng.random(n) < 0.01
    base = T0 + timedelta(days=day)
    return [{"t": base + timedelta(seconds=float(s)), "principal": pid, "tenant": tenant, "operation": str(o), "decision": "deny" if d else "allow"}
            for s, o, d in zip(secs, chosen, denies)]


def _incident(rng: np.random.Generator, kind: str, idx: int, seed: int, day: int, principals: dict[str, list[tuple[str, str]]],
              tenants: list[str]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    base = T0 + timedelta(days=day)
    if kind in ("credential_stuffing", "tenant_probe"):
        pid, tenant = principals["analyst"][int(rng.integers(len(principals["analyst"])))]
    else:
        pid, tenant = principals["manager"][int(rng.integers(len(principals["manager"])))]
    if kind == "credential_stuffing":
        start_s, dur_min, rate, op, decision, tgt = rng.uniform(9, 16) * 3600, rng.uniform(4, 8), rng.uniform(6, 12), "read_order", "deny", tenant
    elif kind == "bulk_export":
        start_s, dur_min, rate, op, decision, tgt = rng.uniform(22, 27) * 3600, rng.uniform(6, 10), rng.uniform(10, 20), "export_report", "allow", tenant
    elif kind == "tenant_probe":
        other = [t for t in tenants if t != tenant][0]
        start_s, dur_min, rate, op, decision, tgt = rng.uniform(9, 16) * 3600, rng.uniform(8, 15), rng.uniform(3, 5), "read_order", "deny", other
    else:
        start_s, dur_min, rate, op, decision, tgt = rng.uniform(20, 22) * 3600, 30.0, 1.0, "export_report", "allow", tenant
    onset = base + timedelta(seconds=float(start_s))
    end = onset + timedelta(minutes=float(dur_min))
    n = max(3, int(rng.poisson(rate * dur_min)))
    secs = np.sort(rng.uniform(0, dur_min * 60, n))
    evs = [{"t": onset + timedelta(seconds=float(s)), "principal": pid, "tenant": tgt, "operation": op, "decision": decision} for s in secs]
    label = {"incident_id": f"INC-{seed}-{idx:02d}", "kind": kind, "principal": pid, "onset": iso(onset), "end": iso(end), "tenant": tenant}
    return evs, label


def generate(seed: int, cfg: dict[str, Any]) -> dict[str, Any]:
    w = cfg["workload"]
    tenants = list(cfg["tenants"])
    rng = np.random.default_rng(seed)
    d_tr, d_dev, d_te = int(w["days_train"]), int(w["days_dev"]), int(w["days_test"])
    people: list[tuple[str, str, str]] = []
    pools: dict[str, list[tuple[str, str]]] = {"analyst": [], "manager": []}
    for t in tenants:
        for role, count in (("manager", w["managers_per_tenant"]), ("analyst", w["analysts_per_tenant"])):
            for i in range(int(count)):
                pid = _pid(seed, t, role, i)
                people.append((pid, t, role))
                pools[role].append((pid, t))
    bursts = {d_tr + d for d in w["burst_days_dev"]} | {d_tr + d_dev + d for d in w["burst_days_test"]}
    raw: list[dict[str, Any]] = []
    for day in range(d_tr + d_dev + d_te):
        for pid, t, role in people:
            raw += _normal_day(rng, pid, t, role, day, day in bursts)
    labels: list[dict[str, Any]] = []
    idx = 0
    for split_start, n_inc, span in ((d_tr, int(w["incidents_dev"]), d_dev), (d_tr + d_dev, int(w["incidents_test"]), d_te)):
        free_days = [d for d in range(split_start, split_start + span - 1) if d not in bursts and (d % 7) < 5]
        for k in range(n_inc):
            kind = KINDS[k % len(KINDS)]
            day = int(free_days[int(rng.integers(len(free_days)))])
            evs, lab = _incident(rng, kind, idx, seed, day, pools, tenants)
            raw += evs
            labels.append(lab)
            idx += 1
    raw.sort(key=lambda e: e["t"])
    events = []
    for i, e in enumerate(raw):
        delay = float(rng.exponential(1.5)) + (float(rng.uniform(10, 60)) if rng.random() < 0.02 else 0.0)
        events.append({"event_time": iso(e["t"]), "arrival_time": iso(e["t"] + timedelta(seconds=delay)), "principal": e["principal"],
                       "tenant": e["tenant"], "operation": e["operation"], "decision": e["decision"], "correlation_id": f"c-{seed}-{i:07d}"})
    split = {"t0": iso(T0), "train_end": iso(T0 + timedelta(days=d_tr)), "dev_end": iso(T0 + timedelta(days=d_tr + d_dev)),
             "test_end": iso(T0 + timedelta(days=d_tr + d_dev + d_te)), "burst_days": sorted(int(b) for b in bursts),
             "notes": "chronological; incidents are generated wholly inside one split; month-end bursts occur in dev and test only"}
    return {"events": events, "labels": labels, "split": split, "seed": seed}


def save(workload: dict[str, Any], out_dir: Path) -> None:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "events.jsonl").open("w", encoding="utf-8") as fh:
        for e in workload["events"]:
            fh.write(json.dumps(e, sort_keys=True) + "\n")
    with (out_dir / "labels.jsonl").open("w", encoding="utf-8") as fh:
        for lab in workload["labels"]:
            fh.write(json.dumps(lab, sort_keys=True) + "\n")
    (out_dir / "split.json").write_text(json.dumps({**workload["split"], "seed": workload["seed"]}, indent=2), encoding="utf-8")
