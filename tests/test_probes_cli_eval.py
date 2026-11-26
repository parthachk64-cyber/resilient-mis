from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request

import pytest

from resilient_mis import cli, evaluate, metrics, report
from resilient_mis.config import load_config
from resilient_mis.http_adapter import make_handler
from resilient_mis.probes import ProbeRunner, readiness_probe, report_probe
from resilient_mis.scenario import inject_fault


# ------------------------------------------------------------------------------------------------------ probes
def test_ledger_expected_and_lost_updates(fx):
    exp = fx.ledger.expected("tenant-a", "ops")
    assert exp["totals_by_currency"] == fx.svc.spending_report(fx.tokens["manager_a"], "tenant-a", "ops").totals_by_currency
    last = fx.svc.store.last_txn()[0]
    fx.client.create(fx.tokens["manager_a"], "tenant-a", "PO-NEW", "ops", "Acme", "USD", 5, "approved")
    assert [r["record_id"] for r in fx.ledger.lost_after(last)] == ["PO-NEW"]
    assert fx.ledger.expected("tenant-a", "ops", up_to_txn=last) == exp


def test_report_probe_detects_wrong_report_outage_and_deadline(fx):
    spec = fx.spec()
    assert report_probe(fx.svc, spec, 5.0).ok
    assert report_probe(fx.svc, spec, 0.0).reason == "deadline_exceeded"
    fx.client.create(fx.tokens["manager_a"], "tenant-a", "PO-GHOST", "ops", "Acme", "USD", 5, "approved")
    spec.up_to_txn = fx.svc.store.last_txn()[0] - 1  # ledger now expects less than the store holds
    assert report_probe(fx.svc, spec, 5.0).reason == "wrong_report"
    spec.up_to_txn = None
    inject_fault(fx.home, "delete")
    assert report_probe(fx.svc, spec, 5.0).reason == "StoreUnavailable"


def test_readiness_requires_all_three_checks(fx):
    spec = fx.spec(revoked=False)
    live_analyst = fx.svc.sessions.login("analyst-a", "dev-analyst-a", "reporting")
    spec.revoked_token = live_analyst  # a NON-revoked analyst can still read: "still denied" must fail
    out = readiness_probe(fx.svc, spec, fx.tokens["manager_a"])
    assert not out.ok and out.checks["revoked_access_still_denied"] is False and out.checks["manager_report_correct"]
    fx.svc.policy.revoke("analyst-a")
    assert readiness_probe(fx.svc, spec, fx.tokens["manager_a"]).ok
    no_write = readiness_probe(fx.svc, spec, fx.tokens["analyst_a"])  # revoked token cannot commit the canary write
    assert not no_write.ok and no_write.checks["new_write_commits"] is False


def test_probe_runner_persists_records_outside_store_and_counts_missing(fx, tmp_path):
    out = tmp_path / "probes.jsonl"
    r = ProbeRunner(fx.svc, fx.spec(), 0.05, 2.0, out, "t")
    r.start()
    time.sleep(0.6)
    recs = r.stop()
    assert recs and out.exists() and not str(out).startswith(str(fx.home.store_path.parent))
    assert [x["seq"] for x in recs] == sorted(x["seq"] for x in recs)
    elapsed_slots = 12
    assert metrics.availability(elapsed_slots, recs, 0.05)["missing"] == max(0, elapsed_slots - len(recs))


def test_probe_runner_overrun_slots_are_missing_not_hidden(fx, tmp_path, monkeypatch):
    import resilient_mis.probes as pr

    orig = pr.report_probe

    def slow(*a, **k):
        time.sleep(0.25)
        return orig(*a, **k)

    monkeypatch.setattr(pr, "report_probe", slow)
    r = ProbeRunner(fx.svc, fx.spec(), 0.05, 2.0, tmp_path / "p.jsonl", "t")
    r.start()
    time.sleep(1.6)
    recs = r.stop()
    seqs = [x["seq"] for x in recs]
    assert len(seqs) >= 2 and len(seqs) < 1.6 / 0.05
    assert all(b - a > 1 for a, b in zip(seqs, seqs[1:]))  # gaps in the sequence = scheduled but never recorded


# ------------------------------------------------------------------------------------------------------ cli
def test_cli_data_validate_exit_codes(tmp_path, capsys):
    good = tmp_path / "g.jsonl"
    good.write_text(json.dumps({"event_time": "2026-03-02T10:00:00Z", "arrival_time": "2026-03-02T10:00:01Z", "principal": "p", "tenant": "t",
                                "operation": "read_order", "decision": "allow", "correlation_id": "c"}))
    assert cli.main(["data-validate", "--events", str(good)]) == 0
    bad = tmp_path / "b.jsonl"
    bad.write_text(json.dumps({"event_time": "nope"}))
    assert cli.main(["data-validate", "--events", str(bad)]) == 2
    assert "INVALID" in capsys.readouterr().out


def test_cli_generate_train_replay_pipeline(tmp_path, capsys):
    cfgp = tmp_path / "c.yaml"
    cfgp.write_text("workload: {days_train: 7, days_dev: 7, days_test: 7, incidents_dev: 4, incidents_test: 4, managers_per_tenant: 1, analysts_per_tenant: 2, burst_days_dev: [1], burst_days_test: [1]}\n")
    base = ["--config", str(cfgp)]
    assert cli.main([*base, "generate-workload", "--out", str(tmp_path / "wl"), "--seed", "3"]) == 0
    assert cli.main([*base, "train", "--workload", str(tmp_path / "wl"), "--run", str(tmp_path / "run"), "--seed", "3"]) == 0
    assert cli.main([*base, "replay", "--run", str(tmp_path / "run"), "--events", str(tmp_path / "wl" / "events.jsonl"), "--after", "2026-03-16T00:00:00Z"]) == 0
    assert (tmp_path / "run" / "alerts.jsonl").exists()
    assert "alert_events" in capsys.readouterr().out


def test_cli_service_commands_end_to_end(tmp_path, capsys, monkeypatch):
    cfgp = tmp_path / "c.yaml"
    cfgp.write_text("rsa_bits: 2048\n")
    home, base = str(tmp_path / "home"), ["--config", str(cfgp)]
    assert cli.main([*base, "init", "--home", home, "--disposable"]) == 0
    for p, role, dep in (("m", "manager", "ops"), ("op", "recovery_operator", None)):
        args = [*base, "grant", "--home", home, "--principal", p, "--role", role, "--tenant", "tenant-a", "--trust-device", f"dev-{p}",
                "--purpose", "reporting" if p == "m" else "operations"]
        assert cli.main(args + (["--department", dep] if dep else [])) == 0
    capsys.readouterr()
    cli.main([*base, "login", "--home", home, "--principal", "m", "--device", "dev-m"])
    mtok = capsys.readouterr().out.strip()
    cli.main([*base, "login", "--home", home, "--principal", "op", "--device", "dev-op", "--purpose", "reporting"])
    optok = capsys.readouterr().out.strip()
    assert cli.main([*base, "order", "create", "--home", home, "--token", mtok, "--tenant", "tenant-a", "--record-id", "PO-1", "--amount-minor", "2500", "--status", "approved"]) == 0
    assert cli.main([*base, "report", "--home", home, "--token", mtok, "--tenant", "tenant-a", "--department", "ops"]) == 0
    assert '"USD": 2500' in capsys.readouterr().out
    assert cli.main([*base, "checkpoint", "--home", home, "--token", optok]) == 2  # purpose "reporting" is not permitted for this operator
    cli.main([*base, "login", "--home", home, "--principal", "op", "--device", "dev-op", "--purpose", "operations"])
    optok = capsys.readouterr().out.strip()
    assert cli.main([*base, "checkpoint", "--home", home, "--token", optok]) == 0
    assert cli.main([*base, "fault", "--home", home, "--kind", "delete"]) == 0
    assert cli.main([*base, "recover", "--home", home, "--token", optok]) == 0
    assert cli.main([*base, "recover", "--home", home, "--token", mtok]) == 2  # a manager may not restore
    assert cli.main([*base, "report", "--home", home, "--token", mtok, "--tenant", "tenant-a", "--department", "ops"]) == 0
    assert cli.main([*base, "order", "read", "--home", home, "--tenant", "tenant-a", "--record-id", "PO-1"]) == 2  # no token


def test_cli_fault_refused_on_non_fixture(tmp_path):
    cfgp = tmp_path / "c.yaml"
    cfgp.write_text("rsa_bits: 2048\n")
    cli.main(["--config", str(cfgp), "init", "--home", str(tmp_path / "prod")])
    with pytest.raises(PermissionError):
        cli.main(["fault", "--home", str(tmp_path / "prod")])


@pytest.mark.slow
def test_walkthrough_end_to_end(tmp_path):
    from resilient_mis import walkthrough

    t = walkthrough.run(tmp_path / "demo", fast=True)
    s = {x["step"]: x for x in t["steps"]}
    assert t["summary"]["ready"] and t["summary"]["lost_committed_updates"] == 0
    assert s["1_manager_reads_department_report"]["totals_verified_against_committed_txns"]
    assert s["4_outage_and_invalid_candidate"]["active_store_untouched"] and "bad_signature" in s["4_outage_and_invalid_candidate"]["invalid_candidate_result"]
    assert s["5_recovery"]["report_total_matches_pre_fault"] and s["5_recovery"]["revoked_analyst_still_denied"]
    assert s["6a_rerun_with_healthy_store"]["outcome"] == "already_restored"
    assert s["6b_interrupt_then_retry"]["orders_in_store_minus_orders_acknowledged_by_clients"] == 0
    with pytest.raises(FileExistsError):
        walkthrough.run(tmp_path / "demo", fast=True)


# ------------------------------------------------------------------------------------------------------ http
def test_http_adapter_uses_same_authorization(fx):
    from http.server import ThreadingHTTPServer

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(fx.svc))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"

    def call(path, token=None, body=None):
        req = urllib.request.Request(base + path, data=None if body is None else json.dumps(body).encode(), method="GET" if body is None else "POST")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    try:
        assert call("/health")[1]["ok"] is True
        code, rep = call("/reports/tenant-a/ops", fx.tokens["manager_a"])
        assert code == 200 and rep["totals_by_currency"] == fx.ledger.expected("tenant-a", "ops")["totals_by_currency"]
        assert call("/reports/tenant-b/ops", fx.tokens["manager_a"]) == (404, {"error": "access denied or record not available"})
        assert call("/orders/tenant-a/PO-NOPE", fx.tokens["manager_a"])[0] == 404
        assert call("/orders/tenant-a/PO-000001")[0] == 404  # no token
        assert call("/orders", fx.tokens["analyst_a"], {"tenant": "tenant-a", "record_id": "PO-H", "department": "ops", "vendor": "V", "currency": "USD", "amount_minor": 1})[0] == 404
        assert call("/orders", fx.tokens["manager_a"], {"tenant": "tenant-a", "record_id": "PO-H", "department": "ops", "vendor": "V", "currency": "USD", "amount_minor": -1})[0] == 400
        assert call("/orders", fx.tokens["manager_a"], {"tenant": "tenant-a", "record_id": "PO-H", "department": "ops", "vendor": "V", "currency": "USD", "amount_minor": 9})[0] == 201
        inject_fault(fx.home, "delete")
        assert call("/reports/tenant-a/ops", fx.tokens["manager_a"])[0] == 503
    finally:
        httpd.shutdown()


# ------------------------------------------------------------------------------------------------------ benchmark smoke
@pytest.mark.slow
def test_benchmark_smoke_and_report_reads_saved_records(tmp_path, cfg):
    c = evaluate.load_smoke(load_config())
    c["rsa_bits"] = 2048
    c["workload"].update({"managers_per_tenant": 1, "analysts_per_tenant": 2})
    c["benchmark"].update({"detection_trials": 1, "recovery_trials": 1, "latency_reps": 4, "snapshot_reps": 2, "orders_per_department": 4})
    c["probes"].update({"observation_s": 3.0, "fault_at_s": 0.5})
    run = tmp_path / "runs" / "smoke"
    run.mkdir(parents=True)
    evaluate.run_manifest(run, c, 1)
    evaluate.run_detection(run, c, 100, 1)
    evaluate.run_recovery(run, c, 1)
    evaluate.latency_trials(run, c)
    md = report.build(run, tmp_path / "docs" / "results.md")
    text = md.read_text(encoding="utf-8")
    for needle in ("C1. Detection", "C2. Recovery time", "C3. Availability", "C4. Latency overhead", "smoke"):
        assert needle in text
    assert (tmp_path / "docs" / "figures" / "fig_recovery_phase_durations.csv").exists()
    # the report must come from saved records: deleting them breaks the build instead of silently recomputing
    for p in (run / "recovery").glob("*.json"):
        p.unlink()
    with pytest.raises(ValueError, match="no saved recovery"):
        report.build(run, tmp_path / "docs" / "again.md")
