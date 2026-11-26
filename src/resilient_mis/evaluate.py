"""Experiment orchestration. Every trial writes a record under ``runs/<id>/``; the report builder reads ONLY those records."""

from __future__ import annotations

import gc
import json
import platform
import random
import shutil
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np

from resilient_mis import __version__, metrics, workload
from resilient_mis.crypto import sha256_hex
from resilient_mis.detection import IsolationDetector, RuleDetector, build_matrix, select_threshold
from resilient_mis.probes import ProbeRunner, readiness_probe
from resilient_mis.recovery import PhaseTimer, recover
from resilient_mis.scenario import build_fixture, inject_fault, wait_until
from resilient_mis.service import Controls
from resilient_mis.snapshots import create_checkpoint, create_snapshot
from resilient_mis.telemetry import load_events, parse_ts


def run_manifest(run_dir: Path, cfg: dict[str, Any], seed: int) -> dict[str, Any]:
    import subprocess

    import cryptography
    import sklearn

    try:
        here = Path(__file__).parent
        commit = subprocess.run(["git", "rev-parse", "--verify", "HEAD"], capture_output=True, text=True, cwd=here, timeout=10).stdout.strip() or "no commit"
        dirty = subprocess.run(["git", "status", "--porcelain", "--", ".", ":!runs", ":!docs"], capture_output=True, text=True, cwd=here.parents[1],
                               timeout=10).stdout.strip()
        if dirty:
            commit += "+uncommitted-changes"
    except Exception:
        commit = "unavailable"
    man = {"run_id": run_dir.name, "package_version": __version__, "git_commit": commit, "seed": seed, "python": sys.version.split()[0],
           "platform": platform.platform(), "processor": platform.processor(), "cryptography": cryptography.__version__,
           "scikit_learn": sklearn.__version__, "numpy": np.__version__, "config_sha256": sha256_hex(json.dumps(cfg, sort_keys=True).encode()),
           "rsa_bits": cfg["rsa_bits"], "scope_note": "single laptop, CPU only, local SQLite, synthetic invented data; not enterprise or cloud performance"}
    (run_dir / "manifest.json").write_text(json.dumps(man, indent=2), encoding="utf-8")
    return man


# ----------------------------------------------------------------------------------------------------------------- detection
def _incident_dt(lab: dict[str, Any]) -> dict[str, Any]:
    return {**lab, "onset": parse_ts(lab["onset"]), "end": parse_ts(lab["end"])}


def detection_trial(seed: int, cfg: dict[str, Any], run_dir: Path | None = None, curve_points: int = 25) -> dict[str, Any]:
    """Generate a workload, fit on earlier normal activity, calibrate on development data, evaluate once on the held-out test split."""
    d = cfg["detection"]
    wl = workload.generate(seed, cfg)
    tmp = Path(tempfile.mkdtemp(prefix="mis-wl-"))
    try:
        workload.save(wl, tmp)
        events = load_events(tmp / "events.jsonl")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    sp = {k: parse_ts(wl["split"][k]) for k in ("t0", "train_end", "dev_end", "test_end")}
    X = build_matrix(events, float(d["window_s"]))
    arr = np.array([e["_arrival_dt"].timestamp() for e in events])
    in_train, in_dev = arr < sp["train_end"].timestamp(), (arr >= sp["train_end"].timestamp()) & (arr < sp["dev_end"].timestamp())
    in_test = arr >= sp["dev_end"].timestamp()
    incidents = [_incident_dt(lab) for lab in wl["labels"]]
    # event-level label: event by an incident principal inside the incident interval (evaluation only)
    pos = np.zeros(len(events), dtype=bool)
    by_p: dict[str, list[dict[str, Any]]] = {}
    for inc in incidents:
        by_p.setdefault(inc["principal"], []).append(inc)
    for k, e in enumerate(events):
        pos[k] = any(i["onset"] <= e["_event_dt"] <= i["end"] for i in by_p.get(e["principal"], ()))
    rules = RuleDetector(d["rules"])
    iforest = IsolationDetector(seed, int(d["iforest"]["n_estimators"]), int(d["iforest"]["max_samples"])).fit(X[in_train])
    s_rule, s_if = rules.score(X), iforest.score(X)
    rule_dev_rate = float(np.mean(s_rule[in_dev & ~pos] >= 1.0)) if np.any(in_dev & ~pos) else 0.0
    thr_if = select_threshold(s_if[in_dev], pos[in_dev], rule_dev_rate)
    hours = (sp["test_end"] - sp["dev_end"]).total_seconds() / 3600.0
    test_inc = [i for i in incidents if i["onset"] >= sp["dev_end"] and i["end"] <= sp["test_end"]]
    arrivals = [e["_arrival_dt"] for e in events]
    principals = [e["principal"] for e in events]

    def evaluate(scores: np.ndarray, thr: float) -> dict[str, Any]:
        mask = in_test & (scores >= thr)
        groups = metrics.alert_groups([(principals[k], arrivals[k]) for k in np.flatnonzero(mask)], float(d["alert_merge_s"]))
        out = metrics.incident_metrics(test_inc, groups, float(d["match_grace_s"]), hours)
        out["event"] = metrics.event_metrics(pos[in_test].tolist(), (scores[in_test] >= thr).tolist())
        return out

    rec: dict[str, Any] = {"trial": f"detection-{seed}", "seed": seed, "split": wl["split"], "monitored_hours_test": hours,
                           "events": {"train": int(in_train.sum()), "dev": int(in_dev.sum()), "test": int(in_test.sum()), "test_positive": int(pos[in_test].sum())},
                           "incidents": {"dev": sum(1 for i in incidents if sp["train_end"] <= i["onset"] < sp["dev_end"]), "test_eligible": len(test_inc),
                                         "by_kind_test": {k: sum(1 for i in test_inc if i["kind"] == k) for k in workload.KINDS}},
                           "thresholds": {"rules": 1.0, "iforest": thr_if, "rule_dev_alert_rate": rule_dev_rate},
                           "detectors": {"rules": evaluate(s_rule, 1.0), "iforest": evaluate(s_if, thr_if)}}
    # per-kind recall for transparency (which incident kinds are missed)
    for name in ("rules", "iforest"):
        miss = set(rec["detectors"][name]["missed"])
        rec["detectors"][name]["recall_by_kind"] = {k: metrics.ratio(sum(1 for i in test_inc if i["kind"] == k and i["incident_id"] not in miss),
                                                                    sum(1 for i in test_inc if i["kind"] == k)) for k in workload.KINDS}
    # operating curve for the Isolation Forest: sweep thresholds over development-score quantiles
    qs = np.linspace(0.0, 0.999, curve_points)
    curve = []
    for q in qs:
        thr = float(np.quantile(s_if[in_dev & ~pos], q))
        ev = evaluate(s_if, thr)
        curve.append({"quantile": float(q), "threshold": thr, "recall": ev["recall"], "false_alerts_per_hour": ev["false_alerts_per_hour"], "precision": ev["precision"]})
    rec["iforest_curve"] = curve
    if run_dir is not None:
        out = Path(run_dir) / "detection"
        out.mkdir(parents=True, exist_ok=True)
        (out / f"trial-{seed}.json").write_text(json.dumps(rec, indent=1, default=_json), encoding="utf-8")
        np.savez_compressed(out / f"scores-{seed}.npz", arrival=arr[in_test], rules=s_rule[in_test], iforest=s_if[in_test], positive=pos[in_test])
    return rec


def _json(o: Any) -> Any:
    if isinstance(o, datetime):
        return o.isoformat()
    if isinstance(o, (np.floating, np.integer)):
        return o.item()
    raise TypeError(type(o))


def run_detection(run_dir: Path, cfg: dict[str, Any], seed0: int = 100, trials: int | None = None) -> list[dict[str, Any]]:
    n = trials or int(cfg["benchmark"]["detection_trials"])
    return [detection_trial(seed0 + k, cfg, run_dir) for k in range(n)]


# ----------------------------------------------------------------------------------------------------------------- recovery
def recovery_trial(trial: int, cfg: dict[str, Any], run_dir: Path, template_keys: Path | None, *, with_journal: bool = True,
                   fault_kind: str = "delete", n_orders: int = 12, post_checkpoint_writes: int = 2) -> dict[str, Any]:
    """One fault -> restore -> verified-ready cycle in a fresh disposable home, with business probes running throughout."""
    pc = cfg["probes"]
    tmp = Path(tempfile.mkdtemp(prefix="mis-trial-"))
    try:
        fx = build_fixture(tmp / "home", cfg, n_orders, seed=1000 + trial, keys_from=template_keys)
        svc, tok = fx.svc, fx.tokens
        cp = create_checkpoint(fx.home, svc.keys, svc.store, time.time)
        svc.policy.revoke("analyst-a")  # access revocation AFTER the checkpoint must survive restore
        for k in range(post_checkpoint_writes):
            fx.client.update(tok["manager_a"], "tenant-a", f"PO-{k + 1:06d}", {"amount_minor": 777_000 + k, "status": "approved"}, 1)
        spec = fx.spec(revoked=True)
        spec.revoked_token = tok["analyst_a"]
        spec.up_to_txn = None
        snapshot_bytes = (Path(cp["path"]) / "store.db.enc").stat().st_size
        runner = ProbeRunner(svc, spec, float(pc["cadence_s"]), float(pc["deadline_s"]), run_dir / "probes" / "probes.jsonl", f"recovery-{trial}")
        timer = PhaseTimer()
        t0 = runner.start()
        time.sleep(float(pc["fault_at_s"]))
        timer.mark("fault_onset")
        inject_fault(fx.home, fault_kind)
        detected = wait_until(lambda: not svc.health()["ok"], 5.0, 0.01)
        timer.mark("detected")
        err = None
        report = None
        try:
            report = recover(svc, tok["recovery"], snapshot=None, use_journal=with_journal, timer=timer)
        except Exception as exc:
            err = f"{type(exc).__name__}: {exc}"
        ready = False
        lost: list[dict[str, Any]] = []
        if report is not None:
            lost = fx.ledger.lost_after(report.restored_last_txn)
            spec.up_to_txn = report.restored_last_txn
            deadline = time.monotonic() + 30.0
            while time.monotonic() < deadline:
                out = readiness_probe(svc, spec, tok["manager_a"], float(pc["deadline_s"]) * 10)
                if out.ok:
                    ready = True
                    timer.mark("ready")
                    break
                time.sleep(0.05)
        rel = time.monotonic() - t0
        time.sleep(max(0.0, float(pc["observation_s"]) - rel) if rel < float(pc["observation_s"]) else 0.5)
        recs = runner.stop()
        stop_rel = time.monotonic() - t0
        scheduled = int(stop_rel // float(pc["cadence_s"]))
        marks = {k: round(v - t0, 6) for k, v in timer.marks.items()}
        rec = {"trial": f"recovery-{trial}", "with_journal": with_journal, "fault_kind": fault_kind, "fault_detected": detected, "ready": ready,
               "error": err, "timeline_s": marks, "durations": timer.durations(), "snapshot_bytes": snapshot_bytes,
               "orders_records": svc.store.count() if ready else None, "lost_confirmed_writes": len(lost),
               "lost_writes_detail": [{"record_id": r["record_id"], "version": r["version"], "txn_id": r["txn_id"]} for r in lost],
               "recovery": report.to_dict() if report else None, "journal_status": report.journal_status if report else None,
               "probe_window": {"scheduled": scheduled, "cadence_s": float(pc["cadence_s"]), "deadline_s": float(pc["deadline_s"]),
                                "records": len(recs), "observation_s": round(stop_rel, 3)},
               "availability": metrics.availability(scheduled, recs, float(pc["cadence_s"])), "key_available": True,
               "storage": "local NTFS/ext4 file system, SQLite synchronous=FULL"}
        (run_dir / "recovery").mkdir(parents=True, exist_ok=True)
        (run_dir / "recovery" / f"trial-{trial:02d}{'' if with_journal else '-nojournal'}.json").write_text(json.dumps(rec, indent=1), encoding="utf-8")
        return rec
    finally:
        gc.collect()
        shutil.rmtree(tmp, ignore_errors=True)


def run_recovery(run_dir: Path, cfg: dict[str, Any], trials: int | None = None) -> list[dict[str, Any]]:
    n = trials or int(cfg["benchmark"]["recovery_trials"])
    tpl = Path(tempfile.mkdtemp(prefix="mis-keys-"))
    try:
        build_fixture(tpl / "h", cfg, 1, with_data=False)
        out = [recovery_trial(k, cfg, run_dir, tpl / "h", with_journal=True, fault_kind="delete" if k % 2 == 0 else "corrupt") for k in range(n)]
        out += [recovery_trial(k, cfg, run_dir, tpl / "h", with_journal=False, fault_kind="delete") for k in range(max(1, n // 2))]
        return out
    finally:
        shutil.rmtree(tpl, ignore_errors=True)


# ----------------------------------------------------------------------------------------------------------------- latency
PROFILES: dict[str, Controls] = {
    "full": Controls(),
    "no_encryption": Controls(encrypt=False),
    "no_authorization": Controls(authorize=False),
    "no_telemetry": Controls(telemetry=False),
    "no_journal": Controls(journal=False),
    "baseline_all_off": Controls(encrypt=False, authorize=False, telemetry=False, journal=False),
}


def latency_trials(run_dir: Path, cfg: dict[str, Any], reps: int | None = None, snap_reps: int | None = None, seed: int = 11) -> dict[str, Any]:
    """Paired, interleaved timings of create / read / report / snapshot under matched fixtures (TEST-ONLY reduced profiles)."""
    b = cfg["benchmark"]
    reps, snap_reps = reps or int(b["latency_reps"]), snap_reps or int(b["snapshot_reps"])
    n_dept = int(b["orders_per_department"])
    tmp = Path(tempfile.mkdtemp(prefix="mis-lat-"))
    rng = random.Random(seed)
    try:
        tpl = build_fixture(tmp / "tpl", cfg, 1, with_data=False)
        fxs = {}
        for name, ctl in PROFILES.items():
            fx = build_fixture(tmp / name, cfg, n_dept, seed=3, keys_from=tmp / "tpl", controls=ctl, bench_only=True)
            fxs[name] = fx
        del tpl
        samples: dict[str, dict[str, list[float]]] = {op: {n: [] for n in PROFILES} for op in ("create", "read", "report")}
        names = list(PROFILES)
        for rep in range(reps):
            for op in ("create", "read", "report"):
                order = names[:]
                rng.shuffle(order)
                for name in order:
                    fx = fxs[name]
                    svc, tk = fx.svc, fx.tokens["manager_a"]
                    t = time.perf_counter_ns()
                    if op == "create":  # created in tenant-b so the tenant-a data that reads and reports touch stays a fixed size
                        svc.create_order(fx.tokens["manager_b"], "tenant-b", f"PO-L{rep:06d}", "ops", "Northwind Supply", "EUR", 12_345 + rep, "approved")
                    elif op == "read":
                        svc.read_order(tk, "tenant-a", f"PO-{rep % n_dept + 1:06d}")
                    else:
                        svc.spending_report(tk, "tenant-a", "ops")
                    samples[op][name].append((time.perf_counter_ns() - t) / 1e6)
        snap = {"protected": [], "baseline": []}
        base_fx, prot_fx = fxs["baseline_all_off"], fxs["full"]
        for _rep in range(snap_reps):
            order = ["protected", "baseline"]
            rng.shuffle(order)
            for which in order:
                if which == "protected":
                    t = time.perf_counter_ns()
                    p = create_snapshot(prot_fx.home, prot_fx.svc.keys, prot_fx.svc.store, time.time)
                    snap["protected"].append((time.perf_counter_ns() - t) / 1e6)
                    shutil.rmtree(p, ignore_errors=True)
                else:
                    dst = tmp / "baseline-copy.db"
                    t = time.perf_counter_ns()
                    base_fx.svc.store.backup_to(dst)
                    snap["baseline"].append((time.perf_counter_ns() - t) / 1e6)
                    dst.unlink()
        cold: list[float] = []
        warm: list[float] = []
        fx = fxs["full"]
        for _rep in range(max(10, reps // 5)):
            fx.svc.keys.drop_cache()
            t = time.perf_counter_ns()
            fx.svc.read_order(fx.tokens["manager_a"], "tenant-a", "PO-000001")
            cold.append((time.perf_counter_ns() - t) / 1e6)
            t = time.perf_counter_ns()
            fx.svc.read_order(fx.tokens["manager_a"], "tenant-a", "PO-000001")
            warm.append((time.perf_counter_ns() - t) / 1e6)
        rec = {"reps": reps, "snapshot_reps": snap_reps, "orders_per_department": n_dept, "concurrency": 1, "load": "sequential, identical request order per rep",
               "timer": "time.perf_counter_ns around the service call; includes authorization, decryption/encryption, telemetry write and journal fsync when enabled; excludes session setup",
               "samples_ms": {op: samples[op] for op in samples}, "snapshot_samples_ms": snap, "first_use_key_load_ms": {"cold_first_read": cold, "warm_second_read": warm},
               "profiles": {n: c.__dict__ for n, c in PROFILES.items()}, "interleaving": "profile order shuffled per repetition (seeded)"}
        (run_dir / "latency").mkdir(parents=True, exist_ok=True)
        (run_dir / "latency" / "samples.json").write_text(json.dumps(rec), encoding="utf-8")
        return rec
    finally:
        gc.collect()
        shutil.rmtree(tmp, ignore_errors=True)


def run_all(run_dir: Path, cfg: dict[str, Any], smoke: bool = False) -> Path:
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    if smoke:
        cfg = load_smoke(cfg)
    run_manifest(run_dir, cfg, seed=100)
    (run_dir / "config.json").write_text(json.dumps(cfg, indent=2, sort_keys=True), encoding="utf-8")
    run_detection(run_dir, cfg)
    run_recovery(run_dir, cfg)
    latency_trials(run_dir, cfg)
    return run_dir


def load_smoke(cfg: dict[str, Any]) -> dict[str, Any]:
    from resilient_mis.config import _merge

    return _merge(cfg, {"rsa_bits": 2048, "workload": {"days_train": 7, "days_dev": 7, "days_test": 7, "incidents_dev": 4, "incidents_test": 8,
                                                      "managers_per_tenant": 2, "analysts_per_tenant": 3, "burst_days_dev": [1], "burst_days_test": [1]},
                        "probes": {"observation_s": 5.0, "fault_at_s": 0.75},
                        "benchmark": {"detection_trials": 2, "recovery_trials": 2, "latency_reps": 15, "snapshot_reps": 3, "orders_per_department": 6}})
