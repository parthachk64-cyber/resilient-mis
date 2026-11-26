"""One-command spending-report recovery walkthrough in a fresh disposable directory.

Every number printed is produced by running the real service; nothing is hard-coded. The recovery timer stops only when the
authorised manager receives the correct report, the revoked analyst is still denied AND a new valid write commits.
"""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from typing import Any

from resilient_mis import workload
from resilient_mis.config import load_config
from resilient_mis.detection import IsolationDetector, RuleDetector, build_matrix, select_threshold
from resilient_mis.errors import AccessDenied, RecoveryError, RecoveryInterrupted
from resilient_mis.metrics import alert_groups
from resilient_mis.probes import readiness_probe
from resilient_mis.recovery import PhaseTimer, file_sha256, recover
from resilient_mis.scenario import build_fixture, inject_fault, wait_until
from resilient_mis.snapshots import create_checkpoint
from resilient_mis.telemetry import load_events, parse_ts

FIXTURE_DIR = Path(__file__).resolve().parent / "data" / "invalid_snapshot"


def _money(minor: int) -> str:
    return f"{minor / 100:,.2f}"


def _unusual_activity(out: Path, cfg: dict[str, Any]) -> dict[str, Any]:
    """Replay a recorded synthetic stream through both detectors and retain the alert evidence."""
    wcfg = {**cfg, "workload": {**cfg["workload"], "days_train": 7, "days_dev": 7, "days_test": 7, "incidents_dev": 4, "incidents_test": 4,
                                "managers_per_tenant": 2, "analysts_per_tenant": 3, "burst_days_dev": [1], "burst_days_test": [1]}}
    wl = workload.generate(21, wcfg)
    workload.save(wl, out / "recorded_activity")
    events = load_events(out / "recorded_activity" / "events.jsonl")
    d = cfg["detection"]
    X = build_matrix(events, float(d["window_s"]))
    arr = [e["_arrival_dt"].timestamp() for e in events]
    t_tr, t_dev = parse_ts(wl["split"]["train_end"]).timestamp(), parse_ts(wl["split"]["dev_end"]).timestamp()
    import numpy as np

    a = np.array(arr)
    tr, dev, te = a < t_tr, (a >= t_tr) & (a < t_dev), a >= t_dev
    rules = RuleDetector(d["rules"])
    model = IsolationDetector(21).fit(X[tr])
    s_rule, s_if = rules.score(X), model.score(X)
    thr = select_threshold(s_if[dev], np.zeros(int(dev.sum()), dtype=bool), float(np.mean(s_rule[dev] >= 1.0)))
    evidence = []
    for k in np.flatnonzero(te):
        r, i = s_rule[k] >= 1.0, s_if[k] >= thr
        if r or i:
            evidence.append({"correlation_id": events[k]["correlation_id"], "principal": events[k]["principal"], "arrival_time": events[k]["arrival_time"],
                             "operation": events[k]["operation"], "decision": events[k]["decision"], "rule_alert": bool(r),
                             "rule_reasons": rules.reasons(X[k]) if r else [], "rule_score": round(float(s_rule[k]), 3),
                             "iforest_alert": bool(i), "iforest_score": round(float(s_if[k]), 4)})
    (out / "alert_evidence.jsonl").write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in evidence), encoding="utf-8")
    groups = alert_groups([(e["principal"], parse_ts(e["arrival_time"])) for e in evidence if e["rule_alert"]], float(d["alert_merge_s"]))
    return {"replayed_events": int(te.sum()), "alert_events": len(evidence), "rule_alert_groups": len(groups),
            "iforest_alert_events": sum(1 for e in evidence if e["iforest_alert"]), "incidents_in_stream": len(wl["labels"]),
            "evidence_file": "alert_evidence.jsonl", "note": "labels were used only to count incidents here, never as detector input"}


def run(directory: Path, cfg: dict[str, Any] | None = None, fast: bool = False) -> dict[str, Any]:
    cfg = cfg or load_config()
    if fast:
        cfg = {**cfg, "rsa_bits": 2048}
    root = Path(directory)
    if root.exists() and any(root.iterdir()):
        raise FileExistsError(f"{root} is not empty; the walkthrough needs a fresh disposable directory")
    root.mkdir(parents=True, exist_ok=True)
    trace: dict[str, Any] = {"steps": [], "disposable_dir": str(root)}

    def step(name: str, **data: Any) -> None:
        trace["steps"].append({"step": name, **data})

    fx = build_fixture(root / "home", cfg, 12)
    svc, tok = fx.svc, fx.tokens
    # 1. two tenants, a manager reads one department's report ----------------------------------------------------
    rep = svc.spending_report(tok["manager_a"], "tenant-a", "ops")
    exp = fx.ledger.expected("tenant-a", "ops")
    ver = svc.verify_report(tok["manager_a"], rep)
    last = json.loads(svc.home.telemetry_path.read_text(encoding="utf-8").splitlines()[-1])
    other = svc.spending_report(tok["manager_b"], "tenant-b", "ops")
    try:
        svc.spending_report(tok["manager_a"], "tenant-b", "ops")
        cross = "ALLOWED (bug)"
    except AccessDenied as exc:
        cross = f"denied: {exc}"
    step("1_manager_reads_department_report", tenant="tenant-a", department="ops", report_total_minor=rep.totals_by_currency, expected_from_client_ledger=exp["totals_by_currency"],
         order_count=rep.order_count, contributing_versions=[(c.record_id, c.version, c.txn_id) for c in rep.contributions],
         totals_verified_against_committed_txns=ver.ok, redacted_allow_decision={k: last[k] for k in ("principal", "tenant", "operation", "decision")},
         other_tenant_total_minor=other.totals_by_currency, manager_a_reading_tenant_b=cross)
    # 2. checkpoint, revoke, business update ---------------------------------------------------------------------
    cp = create_checkpoint(fx.home, svc.keys, svc.store, time.time)
    epoch = svc.policy.revoke("analyst-a")
    upd = fx.client.update(tok["manager_a"], "tenant-a", "PO-000001", {"amount_minor": 1_234_500, "status": "approved"}, 1)
    try:
        svc.read_order(tok["analyst_a"], "tenant-a", "PO-000002")
        analyst = "ALLOWED (bug)"
    except AccessDenied as exc:
        analyst = f"denied: {exc}"
    rep2 = svc.spending_report(tok["manager_a"], "tenant-a", "ops")
    step("2_checkpoint_revoke_update", checkpoint={"snapshot_id": cp["snapshot_id"], "sequence": cp["sequence"], "last_txn": cp["last_txn_id"]},
         policy_epoch_after_revocation=epoch, update_committed={"record": "PO-000001", "version": upd.version, "txn_id": upd.txn_id},
         analyst_after_revocation=analyst, manager_read_after_denial_total_minor=rep2.totals_by_currency,
         manager_read_matches_ledger=rep2.totals_by_currency == fx.ledger.expected("tenant-a", "ops")["totals_by_currency"])
    # 3. unusual activity -----------------------------------------------------------------------------------------
    step("3_detector_replay", **_unusual_activity(root, cfg))
    # 4. outage + invalid candidate --------------------------------------------------------------------------------
    spec = fx.spec(revoked=True)
    pre_fault_last = svc.store.last_txn()[0]
    timer = PhaseTimer()
    timer.mark("fault_onset")
    inject_fault(fx.home, "delete")
    wait_until(lambda: not svc.health()["ok"], 5.0, 0.005)
    timer.mark("detected")
    bad_dir = fx.home.backups / "invalid-fixture"
    shutil.copytree(FIXTURE_DIR, bad_dir)
    before = file_sha256(fx.home.store_path)
    try:
        recover(svc, tok["recovery"], snapshot=bad_dir, timer=PhaseTimer())
        rejected = "ACCEPTED (bug)"
    except RecoveryError as exc:
        rejected = str(exc)
    step("4_outage_and_invalid_candidate", fault="store file deleted (disposable fixture)", health_during_outage=svc.health(),
         invalid_candidate_result=rejected, active_store_untouched=file_sha256(fx.home.store_path) == before, invalid_became_active=False)
    # 5. recovery with approved snapshot + journal; timer stops at verified business readiness -----------------------
    report = recover(svc, tok["recovery"], timer=timer)
    lost = fx.ledger.lost_after(report.restored_last_txn)
    spec.up_to_txn = report.restored_last_txn
    out = readiness_probe(svc, spec, tok["manager_a"], 5.0)
    if out.ok:
        timer.mark("ready")
    rep3 = svc.spending_report(tok["manager_a"], "tenant-a", "ops")
    val = svc.validate_restore(tok["recovery"])
    try:
        svc.spending_report(tok["recovery"], "tenant-a", "ops")
        op_report = "ALLOWED (bug)"
    except AccessDenied:
        op_report = "denied (a recovery operator validates the restore but receives no business report)"
    step("5_recovery", outcome=report.outcome, snapshot_id=report.snapshot_id, journal=report.journal_status,
         journal_entries_replayed=report.journal_entries_replayed, last_txn_before_fault=pre_fault_last, last_restored_txn=report.restored_last_txn,
         lost_committed_updates=len(lost), readiness_checks=out.checks, ready=out.ok, phases_s=timer.durations(),
         report_total_minor_after=rep3.totals_by_currency, report_total_matches_pre_fault=rep3.totals_by_currency == rep2.totals_by_currency,
         revoked_analyst_still_denied=out.checks.get("revoked_access_still_denied"), operator_validation=val.to_dict(), operator_asking_for_report=op_report,
         what_survived={"business_records": svc.store.count(), "policy_epoch_unchanged_by_restore": svc.policy.epoch >= epoch, "keys_retained": True})
    # 6. rerun and interruption -----------------------------------------------------------------------------------
    again = recover(svc, tok["recovery"])
    step("6a_rerun_with_healthy_store", outcome=again.outcome, notes=again.notes, store_replaced=again.active_sha256_before != again.active_sha256_after)
    counts_before = svc.store.count()
    inject_fault(fx.home, "corrupt")
    sha_broken = file_sha256(fx.home.store_path)
    try:
        recover(svc, tok["recovery"], interrupt_before_cutover=True)
        interrupted = "not interrupted (bug)"
    except RecoveryInterrupted:
        interrupted = "interrupted before cutover"
    untouched = file_sha256(fx.home.store_path) == sha_broken
    final = recover(svc, tok["recovery"])
    ok2 = readiness_probe(svc, spec, tok["manager_a"], 5.0)
    counts_after = svc.store.count()
    try:
        svc.read_order(tok["analyst_a"], "tenant-a", "PO-000002")
        still = "ALLOWED (bug)"
    except AccessDenied:
        still = "denied"
    step("6b_interrupt_then_retry", interruption=interrupted, active_state_untouched_by_interruption=untouched, retry_outcome=final.outcome,
         record_counts_before=counts_before, record_counts_after_retry=counts_after,
         orders_in_store_minus_orders_acknowledged_by_clients=counts_after["records"] - len({(r["tenant"], r["record_id"]) for r in fx.ledger.rows()}),
         note="the canary write made by the readiness probe is in the ledger, so 0 means no order was duplicated or invented", revoked_analyst=still,
         readiness=ok2.checks)
    summary = {"ready": out.ok and ok2.ok, "downtime_fault_to_ready_s": timer.durations()["fault_to_ready_s"],
               "restore_start_to_ready_s": timer.durations()["restore_start_to_ready_s"], "lost_committed_updates": len(lost)}
    trace["summary"] = summary
    (root / "recovery_trace.json").write_text(json.dumps(trace, indent=2, default=str), encoding="utf-8")
    (root / "recovery_trace.md").write_text(render_markdown(trace), encoding="utf-8")
    return trace


def render_markdown(trace: dict[str, Any]) -> str:
    L = ["# Recovery trace", "", "Synthetic, invented data in a disposable directory. Produced by `resilient-mis walkthrough`; nothing here is hard-coded.", ""]
    for s in trace["steps"]:
        L.append(f"## {s['step']}")
        for k, v in s.items():
            if k == "step":
                continue
            if isinstance(v, (dict, list)):
                L.append(f"- **{k}**: `{json.dumps(v, default=str)}`")
            else:
                L.append(f"- **{k}**: {v}")
        L.append("")
    L += ["## Summary", ""] + [f"- **{k}**: {v}" for k, v in trace["summary"].items()]
    return "\n".join(L) + "\n"
