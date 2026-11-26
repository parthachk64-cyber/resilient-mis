"""Command line interface. Every command drives the same service and library code the tests and the HTTP adapter use."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from resilient_mis import __version__
from resilient_mis.config import load_config
from resilient_mis.errors import MisError


def _cfg(args: argparse.Namespace) -> dict[str, Any]:
    return load_config(getattr(args, "config", None))


def _svc(args: argparse.Namespace):
    from resilient_mis.service import MisService

    return MisService(Path(args.home), _cfg(args))


def _token(args: argparse.Namespace) -> str:
    tok = args.token or os.environ.get("MIS_TOKEN")
    if not tok:
        raise MisError("a session token is required (--token or MIS_TOKEN); obtain one with `login`")
    return tok


def _print(obj: Any) -> None:
    print(json.dumps(obj, indent=2, default=str))


def cmd_walkthrough(a: argparse.Namespace) -> int:
    from resilient_mis import walkthrough

    d = Path(a.dir) if a.dir else Path(tempfile.mkdtemp(prefix="resilient-mis-demo-"))
    trace = walkthrough.run(d, _cfg(a), fast=a.fast)
    print((d / "recovery_trace.md").read_text(encoding="utf-8"))
    print(f"trace: {d / 'recovery_trace.md'}")
    return 0 if trace["summary"]["ready"] else 1


def cmd_init(a: argparse.Namespace) -> int:
    from resilient_mis.layout import init_home

    h = init_home(Path(a.home), _cfg(a), disposable=a.disposable)
    _print({"home": str(h.root), "disposable_fixture": h.is_disposable_fixture, "tenants": _cfg(a)["tenants"]})
    return 0


def cmd_grant(a: argparse.Namespace) -> int:
    s = _svc(a)
    s.policy.grant(a.principal, a.role, a.tenant, a.department or [], a.purpose or ["reporting"])
    if a.trust_device:
        s.policy.set_device_trust(a.trust_device, True)
    _print({"granted": a.principal, "role": a.role, "policy_epoch": s.policy.epoch})
    return 0


def cmd_revoke(a: argparse.Namespace) -> int:
    _print({"revoked": a.principal, "policy_epoch": _svc(a).policy.revoke(a.principal)})
    return 0


def cmd_login(a: argparse.Namespace) -> int:
    print(_svc(a).sessions.login(a.principal, a.device, a.purpose))
    return 0


def cmd_order(a: argparse.Namespace) -> int:
    s = _svc(a)
    if a.action == "create":
        r = s.create_order(_token(a), a.tenant, a.record_id, a.department, a.vendor, a.currency, a.amount_minor, a.status, a.idem_key)
    elif a.action == "update":
        changes = {k: v for k, v in (("amount_minor", a.amount_minor), ("status", a.status), ("vendor", a.vendor)) if v is not None}
        r = s.update_order(_token(a), a.tenant, a.record_id, changes, a.expected_version, a.idem_key)
    else:
        _print(s.read_order(_token(a), a.tenant, a.record_id).__dict__)
        return 0
    _print(r.__dict__)
    return 0


def cmd_report(a: argparse.Namespace) -> int:
    s = _svc(a)
    rep = s.spending_report(_token(a), a.tenant, a.department)
    out = rep.to_dict()
    out["digest"] = rep.digest()
    out["verified_against_committed_txns"] = s.verify_report(_token(a), rep).ok
    _print(out)
    return 0


def cmd_data_validate(a: argparse.Namespace) -> int:
    from resilient_mis.errors import DataError
    from resilient_mis.telemetry import load_events

    try:
        ev = load_events(Path(a.events))
    except DataError as exc:
        print(f"INVALID: {exc}")
        for p in exc.problems:
            print(f"  - {p}")
        return 2
    print(f"OK: {len(ev)} events, {len({e['principal'] for e in ev})} principals, "
          f"{ev[0]['arrival_time']} .. {ev[-1]['arrival_time']}")
    return 0


def cmd_generate(a: argparse.Namespace) -> int:
    from resilient_mis import workload

    cfg = _cfg(a)
    wl = workload.generate(a.seed, cfg)
    workload.save(wl, Path(a.out))
    _print({"out": a.out, "events": len(wl["events"]), "incidents": len(wl["labels"]), "split": wl["split"]})
    return 0


def cmd_train(a: argparse.Namespace) -> int:
    import joblib
    import numpy as np

    from resilient_mis.detection import IsolationDetector, RuleDetector, build_matrix, select_threshold
    from resilient_mis.telemetry import load_events, parse_ts

    cfg = _cfg(a)
    d = cfg["detection"]
    wd, run = Path(a.workload), Path(a.run)
    run.mkdir(parents=True, exist_ok=True)
    events = load_events(wd / "events.jsonl")
    split = json.loads((wd / "split.json").read_text(encoding="utf-8"))
    X = build_matrix(events, float(d["window_s"]))
    arr = np.array([e["_arrival_dt"].timestamp() for e in events])
    t_tr, t_dev = parse_ts(split["train_end"]).timestamp(), parse_ts(split["dev_end"]).timestamp()
    tr, dev = arr < t_tr, (arr >= t_tr) & (arr < t_dev)
    labels = [json.loads(line) for line in (wd / "labels.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    pos = np.zeros(len(events), dtype=bool)
    for k, e in enumerate(events):
        pos[k] = any(lab["principal"] == e["principal"] and lab["onset"] <= e["event_time"] <= lab["end"] for lab in labels)  # dev calibration only
    rules = RuleDetector(d["rules"])
    model = IsolationDetector(a.seed, int(d["iforest"]["n_estimators"]), int(d["iforest"]["max_samples"])).fit(X[tr])
    rate = float(np.mean(rules.score(X)[dev & ~pos] >= 1.0))
    thr = select_threshold(model.score(X)[dev], pos[dev], rate)
    joblib.dump({"model": model, "threshold": thr, "rules": d["rules"], "window_s": d["window_s"], "seed": a.seed}, run / "detector.joblib")
    _print({"trained_on_events": int(tr.sum()), "dev_events": int(dev.sum()), "iforest_threshold": thr, "rule_dev_alert_rate": rate,
            "model": str(run / "detector.joblib"), "note": "detector.joblib is a pickle: load only files you produced"})
    return 0


def cmd_replay(a: argparse.Namespace) -> int:
    import joblib
    import numpy as np

    from resilient_mis.detection import RuleDetector, build_matrix
    from resilient_mis.telemetry import load_events, parse_ts

    run = Path(a.run)
    bundle = joblib.load(run / "detector.joblib")
    events = load_events(Path(a.events))
    X = build_matrix(events, float(bundle["window_s"]))
    rules = RuleDetector(bundle["rules"])
    s_rule, s_if = rules.score(X), bundle["model"].score(X)
    start = parse_ts(a.after).timestamp() if a.after else 0.0
    rows = []
    for k, e in enumerate(events):
        if e["_arrival_dt"].timestamp() < start:
            continue
        r, i = bool(s_rule[k] >= 1.0), bool(s_if[k] >= bundle["threshold"])
        if r or i:
            rows.append({"correlation_id": e["correlation_id"], "principal": e["principal"], "arrival_time": e["arrival_time"],
                         "rule_alert": r, "rule_reasons": rules.reasons(X[k]) if r else [], "iforest_alert": i, "iforest_score": round(float(s_if[k]), 4)})
    out = run / "alerts.jsonl"
    out.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8")
    _print({"events_replayed": len(events), "alert_events": len(rows), "alerts_file": str(out), "scores_max": float(np.max(s_if)) if len(s_if) else None})
    return 0


def cmd_checkpoint(a: argparse.Namespace) -> int:
    import time

    from resilient_mis.snapshots import create_checkpoint

    s = _svc(a)
    s.authorize_admin(_token(a), "checkpoint")
    _print(create_checkpoint(s.home, s.keys, s.store, time.time))
    return 0


def cmd_verify(a: argparse.Namespace) -> int:
    from resilient_mis.errors import SnapshotError
    from resilient_mis.snapshots import verify_snapshot

    s = _svc(a)
    try:
        v = verify_snapshot(Path(a.snapshot), s.home.trust, expected_tenants=list(s.cfg["tenants"]), require_approved=not a.unapproved_ok)
    except SnapshotError as exc:
        print(f"REJECTED: {exc}")
        return 2
    m = v.manifest
    _print({"verified": True, "snapshot_id": v.snapshot_id, "sequence": m["sequence"], "last_txn_id": m["last_txn_id"], "manifest_sha256": v.manifest_sha256})
    return 0


def cmd_fault(a: argparse.Namespace) -> int:
    from resilient_mis.layout import Home
    from resilient_mis.scenario import inject_fault

    _print({"injected": inject_fault(Home(Path(a.home)), a.kind)})
    return 0


def cmd_recover(a: argparse.Namespace) -> int:
    from resilient_mis.errors import RecoveryInterrupted
    from resilient_mis.recovery import PhaseTimer, recover

    s = _svc(a)
    t = PhaseTimer()
    try:
        r = recover(s, _token(a), snapshot=Path(a.snapshot) if a.snapshot else None, use_journal=not a.no_journal, timer=t,
                    interrupt_before_cutover=a.interrupt_before_cutover)
    except RecoveryInterrupted as exc:
        print(f"INTERRUPTED: {exc}")
        return 3
    _print({**r.to_dict(), "phases_s": t.durations(), "note": "readiness is NOT claimed here: run the business probes (see docs) before declaring service restored"})
    return 0


def cmd_benchmark(a: argparse.Namespace) -> int:
    from resilient_mis import evaluate

    cfg = _cfg(a)
    run = Path(a.run)
    if a.only:
        run.mkdir(parents=True, exist_ok=True)
        if a.smoke:
            cfg = evaluate.load_smoke(cfg)
        evaluate.run_manifest(run, cfg, 100)
        (run / "config.json").write_text(json.dumps(cfg, indent=2, sort_keys=True), encoding="utf-8")
        {"detection": evaluate.run_detection, "recovery": evaluate.run_recovery, "latency": evaluate.latency_trials}[a.only](run, cfg)
    else:
        evaluate.run_all(run, cfg, smoke=a.smoke)
    print(f"run written to {run}")
    return 0


def cmd_report_build(a: argparse.Namespace) -> int:
    from resilient_mis import report

    p = report.build(Path(a.run), Path(a.out), Path(a.figures) if a.figures else None)
    print(f"wrote {p}")
    return 0


def cmd_serve(a: argparse.Namespace) -> int:
    from resilient_mis.http_adapter import serve

    serve(_svc(a), a.host, a.port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="resilient-mis", description="Offline resilient MIS research companion")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--config", help="YAML config overriding configs/default values")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name: str, fn, help_: str):
        sp = sub.add_parser(name, help=help_)
        sp.set_defaults(fn=fn)
        return sp

    s = add("walkthrough", cmd_walkthrough, "run the spending-report recovery walkthrough in a fresh disposable directory")
    s.add_argument("--dir"), s.add_argument("--fast", action="store_true", help="2048-bit RSA instead of 3072 (quicker keygen)")
    s = add("init", cmd_init, "provision keys, store and policy in a new home")
    s.add_argument("--home", required=True), s.add_argument("--disposable", action="store_true", help="mark as a fixture where fault injection is allowed")
    s = add("grant", cmd_grant, "grant a role to a principal")
    s.add_argument("--home", required=True), s.add_argument("--principal", required=True)
    s.add_argument("--role", required=True, choices=["analyst", "manager", "recovery_operator"]), s.add_argument("--tenant", required=True)
    s.add_argument("--department", action="append"), s.add_argument("--purpose", action="append"), s.add_argument("--trust-device")
    s = add("revoke", cmd_revoke, "revoke a principal and every session it holds")
    s.add_argument("--home", required=True), s.add_argument("--principal", required=True)
    s = add("login", cmd_login, "issue a session token (printed once)")
    s.add_argument("--home", required=True), s.add_argument("--principal", required=True), s.add_argument("--device", required=True)
    s.add_argument("--purpose", default="reporting")
    s = add("order", cmd_order, "create, update or read a purchase order")
    s.add_argument("action", choices=["create", "update", "read"]), s.add_argument("--home", required=True), s.add_argument("--token")
    s.add_argument("--tenant", required=True), s.add_argument("--record-id", required=True), s.add_argument("--department", default="ops")
    s.add_argument("--vendor", default="Northwind Supply"), s.add_argument("--currency", default="USD")
    s.add_argument("--amount-minor", type=int), s.add_argument("--status", default=None), s.add_argument("--expected-version", type=int, default=1)
    s.add_argument("--idem-key")
    s = add("report", cmd_report, "departmental spending report (verified against committed transactions)")
    s.add_argument("--home", required=True), s.add_argument("--token"), s.add_argument("--tenant", required=True), s.add_argument("--department", required=True)
    s = add("data-validate", cmd_data_validate, "validate a telemetry CSV/JSONL export")
    s.add_argument("--events", required=True)
    s = add("generate-workload", cmd_generate, "generate synthetic telemetry plus separate scenario labels")
    s.add_argument("--out", required=True), s.add_argument("--seed", type=int, default=1)
    s = add("train", cmd_train, "fit the detectors on the train split and calibrate on the dev split")
    s.add_argument("--workload", required=True), s.add_argument("--run", required=True), s.add_argument("--seed", type=int, default=1)
    s = add("replay", cmd_replay, "score a telemetry file in arrival order with a trained detector")
    s.add_argument("--run", required=True), s.add_argument("--events", required=True), s.add_argument("--after", help="only report alerts at or after this UTC time")
    s = add("checkpoint", cmd_checkpoint, "create and approve a verified checkpoint")
    s.add_argument("--home", required=True), s.add_argument("--token")
    s = add("verify", cmd_verify, "verify a snapshot against the trusted key and approved-checkpoint chain")
    s.add_argument("--home", required=True), s.add_argument("--snapshot", required=True), s.add_argument("--unapproved-ok", action="store_true")
    s = add("fault", cmd_fault, "damage the store of a DISPOSABLE fixture home")
    s.add_argument("--home", required=True), s.add_argument("--kind", choices=["delete", "corrupt"], default="delete")
    s = add("recover", cmd_recover, "restore from the approved checkpoint (+ journal)")
    s.add_argument("--home", required=True), s.add_argument("--token"), s.add_argument("--snapshot"), s.add_argument("--no-journal", action="store_true")
    s.add_argument("--interrupt-before-cutover", action="store_true")
    s = add("benchmark", cmd_benchmark, "run detection, recovery and latency trials into runs/<id>/")
    s.add_argument("--run", required=True), s.add_argument("--smoke", action="store_true", help="tiny CI configuration"), s.add_argument("--only", choices=["detection", "recovery", "latency"])
    s = add("report-build", cmd_report_build, "build results.md, figures and metrics from SAVED trial records")
    s.add_argument("--run", required=True), s.add_argument("--out", default="docs/results.md"), s.add_argument("--figures")
    s = add("serve", cmd_serve, "optional local HTTP adapter over the same service functions")
    s.add_argument("--home", required=True), s.add_argument("--host", default="127.0.0.1"), s.add_argument("--port", type=int, default=8765)
    return p


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except MisError as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
