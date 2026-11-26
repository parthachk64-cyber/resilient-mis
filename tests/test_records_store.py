from __future__ import annotations

import sqlite3
import threading

import pytest

from resilient_mis.errors import ConcurrencyError, IdempotencyConflict, IntegrityError, StoreFenced, StoreUnavailable, ValidationError
from resilient_mis.records import PurchaseOrder, build_report


def po(**kw):
    base = dict(record_id="PO-1", tenant="tenant-a", department="ops", vendor="Acme", currency="USD", amount_minor=1000, version=1, status="approved")
    return PurchaseOrder(**{**base, **kw})


@pytest.mark.parametrize("kw", [dict(amount_minor=-1), dict(amount_minor=True), dict(amount_minor=10.5), dict(currency="usd"), dict(currency="US"),
                                dict(status="paid"), dict(version=0), dict(record_id=""), dict(department="a/b"), dict(amount_minor=10**14)])
def test_invalid_orders_rejected(kw):
    with pytest.raises(ValidationError):
        po(**kw)


def test_update_makes_new_object_and_cannot_change_identity():
    a = po()
    b = a.with_changes(amount_minor=5)
    assert (a.version, a.amount_minor) == (1, 1000) and (b.version, b.amount_minor) == (2, 5)
    for field in ("tenant", "record_id", "version"):
        with pytest.raises(ValidationError):
            a.with_changes(**{field: "x"})


def test_payload_round_trip_and_garbage():
    a = po()
    assert PurchaseOrder.from_bytes(a.to_bytes()) == a
    with pytest.raises(ValidationError):
        PurchaseOrder.from_bytes(b'{"record_id": "x"}')


def test_report_is_deterministic_and_only_counts_approved_department_spend():
    rows = [(po(record_id="PO-2", amount_minor=300), 2), (po(record_id="PO-1", amount_minor=700), 1), (po(record_id="PO-3", status="draft"), 3),
            (po(record_id="PO-4", department="hr"), 4)]
    r1, r2 = build_report("tenant-a", "ops", rows, 4), build_report("tenant-a", "ops", list(reversed(rows)), 4)
    assert r1 == r2 and r1.digest() == r2.digest()
    assert r1.totals_by_currency == {"USD": 1000} and r1.txn_ids == [1, 2] and r1.order_count == 2


def test_empty_report_totals_zero_orders():
    r = build_report("tenant-a", "ops", [], 0)
    assert r.totals_by_currency == {} and r.order_count == 0


# ---------------------------------------------------------------------------------------------------------- store
def test_idempotent_write_does_not_duplicate(fx):
    tk = fx.tokens["manager_a"]
    r1 = fx.svc.create_order(tk, "tenant-a", "PO-DUP", "ops", "Acme", "USD", 100, "approved", idem_key="k1")
    r2 = fx.svc.create_order(tk, "tenant-a", "PO-DUP", "ops", "Acme", "USD", 100, "approved", idem_key="k1")
    assert (r1.txn_id, r1.version) == (r2.txn_id, r2.version) and not r1.duplicate and r2.duplicate
    assert fx.svc.store.count()["record_versions"] == fx.svc.store.count()["txns"]


def test_idempotency_key_reuse_for_different_write_conflicts(fx):
    tk = fx.tokens["manager_a"]
    fx.svc.create_order(tk, "tenant-a", "PO-K", "ops", "Acme", "USD", 100, "approved", idem_key="same")
    with pytest.raises(IdempotencyConflict):
        fx.svc.create_order(tk, "tenant-a", "PO-K", "ops", "Acme", "USD", 999, "approved", idem_key="same")
    with pytest.raises(IdempotencyConflict):
        fx.svc.create_order(tk, "tenant-a", "PO-OTHER", "ops", "Acme", "USD", 100, "approved", idem_key="same")


def test_stale_expected_version_is_a_concurrency_error(fx):
    tk = fx.tokens["manager_a"]
    fx.svc.update_order(tk, "tenant-a", "PO-000001", {"amount_minor": 5}, 1)
    with pytest.raises(ConcurrencyError) as e:
        fx.svc.update_order(tk, "tenant-a", "PO-000001", {"amount_minor": 6}, 1)
    assert e.value.current_version == 2


def test_idempotent_replay_of_update_returns_original_receipt(fx):
    tk = fx.tokens["manager_a"]
    a = fx.svc.update_order(tk, "tenant-a", "PO-000001", {"amount_minor": 5}, 1, idem_key="u1")
    b = fx.svc.update_order(tk, "tenant-a", "PO-000001", {"amount_minor": 5}, 1, idem_key="u1")
    assert b.duplicate and b.txn_id == a.txn_id


def test_concurrent_writers_exactly_one_wins(fx):
    tk, results = fx.tokens["manager_a"], []

    def worker(i):
        try:
            fx.svc.update_order(tk, "tenant-a", "PO-000001", {"amount_minor": 1000 + i}, 1, idem_key=f"w{i}")
            results.append("ok")
        except ConcurrencyError:
            results.append("conflict")

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert results.count("ok") == 1 and results.count("conflict") == 5
    assert fx.svc.store.verify_chain() == fx.svc.store.count()["txns"]


def test_hash_chain_detects_edit_and_deletion(fx):
    store = fx.svc.store
    assert store.verify_chain() > 0
    con = sqlite3.connect(fx.home.store_path)
    con.execute("UPDATE txns SET committed_at = '2000-01-01T00:00:00Z' WHERE txn_id = 3")
    con.commit(), con.close()
    with pytest.raises(IntegrityError):
        store.verify_chain()


def test_deleted_middle_transaction_detected(fx):
    con = sqlite3.connect(fx.home.store_path)
    con.execute("DELETE FROM records WHERE txn_id = 2")
    con.execute("DELETE FROM txns WHERE txn_id = 2")
    con.commit(), con.close()
    with pytest.raises(IntegrityError):
        fx.svc.store.verify_chain()


def test_missing_and_corrupt_store_are_unavailable(fx):
    fx.home.store_path.write_bytes(b"not a database" * 100)
    with pytest.raises(StoreUnavailable):
        fx.svc.store.last_txn()
    fx.home.store_path.unlink()
    assert fx.svc.health()["ok"] is False


def test_fence_blocks_and_drains(fx):
    fx.svc.store.fence()
    try:
        with pytest.raises(StoreFenced):
            fx.svc.store.last_txn()
        assert fx.svc.store.wait_idle(1.0)
    finally:
        fx.svc.store.unfence()
    assert fx.svc.store.last_txn()[0] > 0


def test_backup_copy_is_consistent(fx, tmp_path):
    fx.svc.store.backup_to(tmp_path / "copy.db")
    con = sqlite3.connect(tmp_path / "copy.db")
    assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert con.execute("SELECT COUNT(*) FROM txns").fetchone()[0] == fx.svc.store.count()["txns"]
    con.close()
