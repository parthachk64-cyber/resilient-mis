from __future__ import annotations

import base64
import json
import shutil
import time
from pathlib import Path

import pytest
from conftest import corrupt_file

from resilient_mis.errors import AccessDenied, RecoveryError, RecoveryInterrupted
from resilient_mis.keys import KeyStore
from resilient_mis.probes import readiness_probe
from resilient_mis.recovery import PhaseTimer, file_sha256, recover
from resilient_mis.scenario import inject_fault
from resilient_mis.snapshots import create_checkpoint, create_snapshot, verify_snapshot
from resilient_mis.walkthrough import FIXTURE_DIR

TENANTS = ["tenant-a", "tenant-b"]


def checkpoint(fx):
    return create_checkpoint(fx.home, fx.svc.keys, fx.svc.store, time.time)


def test_snapshot_round_trip_restores_exact_business_state(fx):
    cp = checkpoint(fx)
    before = fx.svc.validate_restore(fx.tokens["recovery"])
    inject_fault(fx.home, "delete")
    rep = recover(fx.svc, fx.tokens["recovery"])
    after = fx.svc.validate_restore(fx.tokens["recovery"])
    assert rep.outcome == "restored" and rep.snapshot_id == cp["snapshot_id"]
    assert (before.last_txn_id, before.business_digest) == (after.last_txn_id, after.business_digest)


def test_invalid_fixture_candidate_never_becomes_active(fx):
    checkpoint(fx)
    inject_fault(fx.home, "corrupt")
    bad = fx.home.backups / "bad"
    shutil.copytree(FIXTURE_DIR, bad)
    before = file_sha256(fx.home.store_path)
    with pytest.raises(RecoveryError, match="bad_signature"):
        recover(fx.svc, fx.tokens["recovery"], snapshot=bad)
    assert file_sha256(fx.home.store_path) == before
    assert not fx.svc.health()["ok"]


def test_stale_but_valid_snapshot_is_detected(fx):
    first = checkpoint(fx)
    fx.client.create(fx.tokens["manager_a"], "tenant-a", "PO-LATE", "ops", "Acme", "USD", 5, "approved")
    checkpoint(fx)
    with pytest.raises(Exception, match="stale_snapshot"):
        verify_snapshot(Path(first["path"]), fx.home.trust)
    inject_fault(fx.home, "delete")
    with pytest.raises(RecoveryError, match="stale_snapshot"):
        recover(fx.svc, fx.tokens["recovery"], snapshot=Path(first["path"]))
    assert recover(fx.svc, fx.tokens["recovery"]).outcome == "restored"  # latest approved is accepted by default


def test_unapproved_snapshot_is_refused(fx):
    path = create_snapshot(fx.home, fx.svc.keys, fx.svc.store, time.time)
    with pytest.raises(Exception, match="not_approved"):
        verify_snapshot(path, fx.home.trust)
    assert verify_snapshot(path, fx.home.trust, require_approved=False).snapshot_id == path.name


@pytest.mark.parametrize("attack,reason", [("blob", "digest_mismatch"), ("manifest_edit", "bad_signature"), ("sig", "bad_signature"), ("missing_blob", "missing_file"),
                                           ("scope", "bad_signature")])
def test_manifest_and_file_tampering_is_detected(fx, attack, reason):
    cp = checkpoint(fx)
    p = Path(cp["path"])
    if attack == "blob":
        corrupt_file(p / "store.db.enc")
    elif attack == "manifest_edit":
        m = json.loads((p / "manifest.json").read_text())
        m["last_txn_id"] += 1
        (p / "manifest.json").write_text(json.dumps(m))
    elif attack == "scope":
        m = json.loads((p / "manifest.json").read_text())
        m["scope"]["tenants"] = ["tenant-a"]
        (p / "manifest.json").write_text(json.dumps(m))
    elif attack == "sig":
        (p / "manifest.sig").write_text(base64.b64encode(b"x" * 64).decode())
    else:
        (p / "store.db.enc").unlink()
    with pytest.raises(Exception, match=reason):
        verify_snapshot(p, fx.home.trust)


def test_verification_key_must_match_pinned_anchor(fx, tmp_path):
    cp = checkpoint(fx)
    other = KeyStore.create(tmp_path / "other", TENANTS, rsa_bits=2048)
    shutil.copy(other.trust_dir / "manifest-verify.pub", fx.home.trust / "manifest-verify.pub")
    with pytest.raises(Exception, match="anchor_mismatch"):
        verify_snapshot(Path(cp["path"]), fx.home.trust)


def test_tampered_approved_checkpoint_chain_is_rejected(fx):
    cp = checkpoint(fx)
    chain = fx.home.trust / "checkpoints.jsonl"
    d = json.loads(chain.read_text())
    d["body"]["sequence"] = 99
    chain.write_text(json.dumps(d) + "\n")
    with pytest.raises(Exception, match="checkpoint_chain_invalid"):
        verify_snapshot(Path(cp["path"]), fx.home.trust)


def test_scope_must_match_deployment(fx):
    cp = checkpoint(fx)
    with pytest.raises(Exception, match="scope_mismatch"):
        verify_snapshot(Path(cp["path"]), fx.home.trust, expected_tenants=["tenant-a"])


def test_access_revocation_after_checkpoint_survives_restore(fx):
    checkpoint(fx)
    fx.svc.policy.revoke("analyst-a")
    epoch = fx.svc.policy.epoch
    inject_fault(fx.home, "delete")
    recover(fx.svc, fx.tokens["recovery"])
    assert fx.svc.policy.epoch == epoch
    with pytest.raises(AccessDenied):
        fx.svc.read_order(fx.tokens["analyst_a"], "tenant-a", "PO-000001")
    assert fx.svc.read_order(fx.tokens["manager_a"], "tenant-a", "PO-000001")


def test_journal_recovers_writes_after_checkpoint_and_snapshot_only_loses_them(fx):
    checkpoint(fx)
    fx.client.update(fx.tokens["manager_a"], "tenant-a", "PO-000001", {"amount_minor": 42}, 1)
    inject_fault(fx.home, "delete")
    snap_only = recover(fx.svc, fx.tokens["recovery"], use_journal=False)
    assert snap_only.journal_status == "disabled" and len(fx.ledger.lost_after(snap_only.restored_last_txn)) == 1
    inject_fault(fx.home, "delete")
    full = recover(fx.svc, fx.tokens["recovery"])
    assert full.journal_status == "replayed" and fx.ledger.lost_after(full.restored_last_txn) == []
    assert fx.svc.read_order(fx.tokens["manager_a"], "tenant-a", "PO-000001").amount_minor == 42


@pytest.mark.parametrize("damage", ["flip", "truncate_middle", "forged_entry"])
def test_damaged_journal_is_rejected_and_falls_back_to_snapshot(fx, damage):
    checkpoint(fx)
    for i in range(3):
        fx.client.create(fx.tokens["manager_a"], "tenant-a", f"PO-J{i}", "ops", "Acme", "USD", 10 + i, "approved")
    lines = fx.home.journal_path.read_text().splitlines()
    if damage == "flip":
        d = json.loads(lines[-1])
        d["envelope"]["ct"] = d["envelope"]["ct"][::-1]
        lines[-1] = json.dumps(d, sort_keys=True, separators=(",", ":"))
    elif damage == "truncate_middle":
        del lines[len(lines) // 2]
    else:
        d = json.loads(lines[-1])
        d["txn"]["version"] = 9
        lines[-1] = json.dumps(d, sort_keys=True, separators=(",", ":"))
    fx.home.journal_path.write_text("\n".join(lines) + "\n")
    inject_fault(fx.home, "delete")
    rep = recover(fx.svc, fx.tokens["recovery"])
    assert rep.journal_status.startswith("rejected") and rep.journal_entries_replayed == 0
    assert fx.svc.validate_restore(fx.tokens["recovery"]).ok


def test_rerun_with_healthy_store_is_a_noop_that_keeps_later_writes(fx):
    checkpoint(fx)
    inject_fault(fx.home, "delete")
    recover(fx.svc, fx.tokens["recovery"])
    fx.client.create(fx.tokens["manager_a"], "tenant-a", "PO-AFTER", "ops", "Acme", "USD", 7, "approved")
    count = fx.svc.store.count()
    again = recover(fx.svc, fx.tokens["recovery"])
    assert again.outcome == "already_restored" and fx.svc.store.count() == count
    assert fx.svc.read_order(fx.tokens["manager_a"], "tenant-a", "PO-AFTER").amount_minor == 7


def test_interruption_before_cutover_leaves_active_state_and_retry_does_not_duplicate(fx):
    checkpoint(fx)
    fx.client.update(fx.tokens["manager_a"], "tenant-a", "PO-000001", {"amount_minor": 11}, 1)
    fx.svc.policy.revoke("analyst-a")
    inject_fault(fx.home, "corrupt")
    broken = file_sha256(fx.home.store_path)
    with pytest.raises(RecoveryInterrupted):
        recover(fx.svc, fx.tokens["recovery"], interrupt_before_cutover=True)
    assert file_sha256(fx.home.store_path) == broken
    rep = recover(fx.svc, fx.tokens["recovery"])
    ok = readiness_probe(fx.svc, fx.spec(), fx.tokens["manager_a"])
    assert rep.outcome == "restored" and ok.ok
    assert fx.svc.store.count()["records"] == len({(r["tenant"], r["record_id"]) for r in fx.ledger.rows()})
    with pytest.raises(AccessDenied):
        fx.svc.read_order(fx.tokens["analyst_a"], "tenant-a", "PO-000001")


def test_interruption_with_healthy_active_store_does_not_damage_it(fx):
    checkpoint(fx)
    before = file_sha256(fx.home.store_path)
    with pytest.raises(RecoveryInterrupted):
        recover(fx.svc, fx.tokens["recovery"], interrupt_before_cutover=True)
    assert file_sha256(fx.home.store_path) == before and fx.svc.health()["ok"]


def test_restore_requires_recovery_operator(fx):
    checkpoint(fx)
    for who in ("manager_a", "analyst_a"):
        with pytest.raises(AccessDenied):
            recover(fx.svc, fx.tokens[who])


def test_nothing_to_restore_without_an_approved_checkpoint(fx):
    inject_fault(fx.home, "delete")
    with pytest.raises(RecoveryError, match="no approved checkpoint"):
        recover(fx.svc, fx.tokens["recovery"])


def test_missing_backup_key_fails_closed_and_leaves_store_alone(fx):
    checkpoint(fx)
    inject_fault(fx.home, "corrupt")
    before = file_sha256(fx.home.store_path)
    (fx.home.keys / f"{fx.svc.keys.latest_key_id('backup')}.pem").unlink()
    fx.svc.keys.drop_cache()
    with pytest.raises(RecoveryError, match="key_unavailable|decrypted"):
        recover(fx.svc, fx.tokens["recovery"])
    assert file_sha256(fx.home.store_path) == before


def test_unverifiable_active_store_is_replaced_by_a_verified_restore(fx):
    checkpoint(fx)
    import sqlite3

    con = sqlite3.connect(fx.home.store_path)
    con.execute("UPDATE txns SET entry_hash = 'f' * 64 WHERE txn_id = (SELECT MAX(txn_id) FROM txns)".replace("'f' * 64", "'" + "f" * 64 + "'"))
    con.commit(), con.close()
    # an active store whose hash chain no longer verifies is unhealthy, so it is replaced; it must end verified
    assert not fx.svc.validate_restore(fx.tokens["recovery"]).ok
    assert recover(fx.svc, fx.tokens["recovery"]).outcome == "restored"
    assert fx.svc.validate_restore(fx.tokens["recovery"]).ok


def test_phase_timer_rejects_unknown_phase_and_computes_durations():
    t = PhaseTimer()
    with pytest.raises(ValueError):
        t.mark("bogus")
    t.mark("fault_onset", 10.0), t.mark("restore_start", 10.5), t.mark("ready", 12.0)
    d = t.durations()
    assert d["fault_to_ready_s"] == 2.0 and d["restore_start_to_ready_s"] == 1.5 and d["fault_to_detected_s"] is None


def test_fault_injection_refused_outside_disposable_fixture(tmp_path, cfg, key_template):
    from resilient_mis.layout import init_home
    from resilient_mis.scenario import inject_fault as inject

    home = init_home(tmp_path / "prod-like", cfg, disposable=False)
    with pytest.raises(PermissionError):
        inject(home, "delete")
    assert home.store_path.exists()
