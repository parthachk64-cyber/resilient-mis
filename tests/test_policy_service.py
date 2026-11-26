from __future__ import annotations

import json
import sqlite3
import time

import pytest

from resilient_mis.errors import AccessDenied, IntegrityError, MisError
from resilient_mis.service import Controls, MisService


def test_manager_reads_report_and_matches_ledger(fx):
    rep = fx.svc.spending_report(fx.tokens["manager_a"], "tenant-a", "ops")
    assert rep.totals_by_currency == fx.ledger.expected("tenant-a", "ops")["totals_by_currency"]
    assert fx.svc.verify_report(fx.tokens["manager_a"], rep).ok


def test_per_tenant_isolation(fx):
    with pytest.raises(AccessDenied):
        fx.svc.spending_report(fx.tokens["manager_a"], "tenant-b", "ops")
    with pytest.raises(AccessDenied):
        fx.svc.read_order(fx.tokens["manager_b"], "tenant-a", "PO-000001")
    assert fx.svc.spending_report(fx.tokens["manager_b"], "tenant-b", "ops").totals_by_currency.keys() == {"EUR"}


def test_per_role_and_department(fx):
    a = fx.tokens["analyst_a"]
    assert fx.svc.read_order(a, "tenant-a", "PO-000001").department == "ops"
    with pytest.raises(AccessDenied):
        fx.svc.create_order(a, "tenant-a", "PO-X", "ops", "Acme", "USD", 1)  # role
    with pytest.raises(AccessDenied):
        fx.svc.export_report(a, "tenant-a", "ops")
    with pytest.raises(AccessDenied):
        fx.svc.spending_report(a, "tenant-a", "research")  # department
    with pytest.raises(AccessDenied):
        fx.svc.read_order(a, "tenant-a", "PO-R00001")  # decrypted record belongs to a department the analyst may not see


def test_recovery_operator_cannot_read_business_data_but_can_validate(fx):
    op = fx.tokens["recovery"]
    for call in (lambda: fx.svc.spending_report(op, "tenant-a", "ops"), lambda: fx.svc.read_order(op, "tenant-a", "PO-000001"),
                 lambda: fx.svc.export_report(op, "tenant-a", "ops")):
        with pytest.raises(AccessDenied):
            call()
    v = fx.svc.validate_restore(op)
    assert v.ok and v.decrypted == v.record_versions
    assert "amount" not in json.dumps(v.to_dict())
    with pytest.raises(AccessDenied):
        fx.svc.validate_restore(fx.tokens["manager_a"])


def test_denied_and_missing_are_indistinguishable(fx):
    m = fx.tokens["manager_a"]
    with pytest.raises(AccessDenied) as missing:
        fx.svc.read_order(m, "tenant-a", "PO-NOPE")
    with pytest.raises(AccessDenied) as other_tenant:
        fx.svc.read_order(m, "tenant-b", "PO-000001")
    with pytest.raises(AccessDenied) as no_session:
        fx.svc.read_order("garbage", "tenant-a", "PO-000001")
    assert str(missing.value) == str(other_tenant.value) == str(no_session.value)


def test_revocation_takes_effect_on_existing_session_immediately(fx):
    a = fx.tokens["analyst_a"]
    assert fx.svc.read_order(a, "tenant-a", "PO-000001")
    fx.svc.policy.revoke("analyst-a")
    with pytest.raises(AccessDenied):
        fx.svc.read_order(a, "tenant-a", "PO-000001")
    with pytest.raises(AccessDenied):
        fx.svc.sessions.login("analyst-a", "dev-analyst-a", "reporting")


def test_trusted_context_change_applies_to_existing_session(fx):
    m = fx.tokens["manager_a"]
    assert fx.svc.spending_report(m, "tenant-a", "ops")
    fx.svc.policy.set_device_trust("dev-mgr-a", False)
    with pytest.raises(AccessDenied):
        fx.svc.spending_report(m, "tenant-a", "ops")
    fx.svc.policy.set_device_trust("dev-mgr-a", True)
    assert fx.svc.spending_report(m, "tenant-a", "ops")


def test_purpose_must_be_permitted(fx):
    fx.svc.policy.grant("mgr-a", "manager", "tenant-a", ["ops"], ["reporting"])
    tok = fx.svc.sessions.login("mgr-a", "dev-mgr-a", "audit")
    with pytest.raises(AccessDenied):
        fx.svc.spending_report(tok, "tenant-a", "ops")


def test_expired_session_denied(fx, cfg):
    clock = {"t": time.time()}
    svc = MisService(fx.home, cfg, clock=lambda: clock["t"])
    tok = svc.sessions.login("mgr-a", "dev-mgr-a", "reporting")
    assert svc.spending_report(tok, "tenant-a", "ops")
    clock["t"] += cfg["service"]["session_ttl_s"] + 1
    with pytest.raises(AccessDenied):
        svc.spending_report(tok, "tenant-a", "ops")


def test_swapped_ciphertext_between_records_fails_identity_binding(fx):
    con = sqlite3.connect(fx.home.store_path)
    a = con.execute("SELECT envelope FROM records WHERE tenant='tenant-a' AND record_id='PO-000001'").fetchone()[0]
    con.execute("UPDATE records SET envelope=? WHERE tenant='tenant-a' AND record_id='PO-000002'", (a,))
    con.commit(), con.close()
    with pytest.raises(IntegrityError):
        fx.svc.read_order(fx.tokens["manager_a"], "tenant-a", "PO-000002")


def test_tampered_report_is_caught_by_verification(fx):
    from dataclasses import replace

    m = fx.tokens["manager_a"]
    rep = fx.svc.spending_report(m, "tenant-a", "ops")
    forged = replace(rep, totals_by_currency={"USD": rep.totals_by_currency["USD"] + 1})
    assert not fx.svc.verify_report(m, forged).ok
    bad_txn = replace(rep, contributions=(replace(rep.contributions[0], txn_id=9999),) + rep.contributions[1:])
    assert not fx.svc.verify_report(m, bad_txn).ok


def test_telemetry_is_minimal_and_free_of_secrets(fx):
    m = fx.tokens["manager_a"]
    fx.svc.spending_report(m, "tenant-a", "ops")
    with pytest.raises(AccessDenied):
        fx.svc.read_order(fx.tokens["analyst_a"], "tenant-b", "PO-000001")
    text = fx.home.telemetry_path.read_text(encoding="utf-8")
    rows = [json.loads(line) for line in text.splitlines()]
    assert {"allow", "deny"} <= {r["decision"] for r in rows}
    assert set(rows[0]) == {"event_time", "arrival_time", "principal", "tenant", "operation", "decision", "correlation_id"}
    for secret in (m, fx.tokens["analyst_a"], "mgr-a", "analyst-a", "Northwind", "PO-000001"):
        assert secret not in text


def test_reduced_protection_controls_are_refused_outside_the_benchmark_harness(fx, cfg):
    with pytest.raises(MisError):
        MisService(fx.home, cfg, controls=Controls(encrypt=False))
    with pytest.raises(MisError):
        MisService(fx.home, cfg, controls=Controls(authorize=False))


def test_export_is_authorised_and_deterministic(fx):
    a = fx.svc.export_report(fx.tokens["manager_a"], "tenant-a", "ops")
    b = fx.svc.export_report(fx.tokens["manager_a"], "tenant-a", "ops")
    assert a == b and a.startswith(b"record_id,version,txn_id,amount_minor,currency")


def test_invalid_input_never_reaches_the_store(fx):
    before = fx.svc.store.count()
    for bad in (dict(amount_minor=-5), dict(currency="dollars"), dict(status="paid")):
        kw = dict(record_id="PO-BAD", department="ops", vendor="Acme", currency="USD", amount_minor=1, status="draft") | bad
        with pytest.raises(MisError):
            fx.svc.create_order(fx.tokens["manager_a"], "tenant-a", **kw)
    assert fx.svc.store.count() == before


def test_reopen_data_from_a_new_process(fx):
    import os
    import subprocess
    import sys

    env = {**os.environ, "MIS_TOKEN": fx.tokens["manager_a"]}
    out = subprocess.run([sys.executable, "-m", "resilient_mis.cli", "report", "--home", str(fx.home.root), "--tenant", "tenant-a", "--department", "ops"],
                         capture_output=True, text=True, env=env, timeout=120)
    assert out.returncode == 0, out.stderr
    data = json.loads(out.stdout)
    assert data["totals_by_currency"] == fx.ledger.expected("tenant-a", "ops")["totals_by_currency"] and data["verified_against_committed_txns"] is True
