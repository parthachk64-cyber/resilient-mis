"""The MIS service: every operation authorises FIRST, then decrypts, aggregates, exports or restores.

Both the CLI and the optional HTTP adapter call these methods; there is no second code path.
Denied requests and missing records are indistinguishable to the caller (``AccessDenied``).
"""

from __future__ import annotations

import csv
import io
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from resilient_mis import crypto
from resilient_mis.config import load_config
from resilient_mis.errors import AccessDenied, IdempotencyConflict, IntegrityError, MisError, StoreUnavailable, ValidationError
from resilient_mis.identity import SessionProvider
from resilient_mis.journal import Journal
from resilient_mis.keys import KeyStore
from resilient_mis.layout import Home, as_home
from resilient_mis.policy import Decision, PolicyStore
from resilient_mis.records import SCHEMA, PurchaseOrder, SpendingReport, build_report
from resilient_mis.store import CommitResult, Store
from resilient_mis.telemetry import Telemetry
from resilient_mis.verify import StoreVerification, verify_store


@dataclass(frozen=True)
class Controls:
    """Individual protections. All True in production; reduced profiles exist only for the benchmark harness."""

    encrypt: bool = True
    authorize: bool = True
    telemetry: bool = True
    journal: bool = True

    @property
    def is_full(self) -> bool:
        return self.encrypt and self.authorize and self.telemetry and self.journal


@dataclass(frozen=True)
class Receipt:
    tenant: str
    record_id: str
    version: int
    txn_id: int
    duplicate: bool
    correlation_id: str


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    problems: tuple[str, ...]


class MisService:
    def __init__(self, home: Home | str | Path, config: dict[str, Any] | None = None, *, controls: Controls | None = None,
                 clock: Callable[[], float] = time.time, _bench_only: bool = False) -> None:
        self.home = as_home(home)
        self.cfg = config or load_config()
        self.controls = controls or Controls()
        if not self.controls.is_full and not _bench_only:
            raise MisError("reduced-protection controls are test-only and cannot be enabled on a service")
        self.clock = clock
        self.keys = KeyStore(self.home.root)
        self.store = Store(self.home.store_path)
        self.policy = PolicyStore(self.home.policy_path)
        self.sessions = SessionProvider(self.policy, float(self.cfg["service"]["session_ttl_s"]), clock)
        self.journal = Journal(self.home.journal_path, self.keys)
        self.telemetry = Telemetry(self.home.telemetry_path, self.keys, clock)

    # -- authorisation ----------------------------------------------------------------------------------------
    def _decide(self, token: str, op: str, tenant: str | None, department: str | None = None) -> Decision:
        if not self.controls.authorize:
            return Decision(True, "ok", "bench", "manager", tenant, ("*",))
        return self.policy.decide(token, op, tenant, department, self.clock())

    def _emit(self, d: Decision, op: str, tenant: str | None, corr: str, allowed: bool) -> None:
        if self.controls.telemetry:
            self.telemetry.emit(d.principal, tenant, op, "allow" if allowed else "deny", corr)

    def _deny(self, d: Decision, op: str, tenant: str | None, corr: str) -> AccessDenied:
        self._emit(d, op, tenant, corr, False)
        return AccessDenied()

    def _require(self, token: str, op: str, tenant: str | None, department: str | None, corr: str) -> Decision:
        d = self._decide(token, op, tenant, department)
        if not d.allow:
            raise self._deny(d, op, tenant, corr)
        return d

    def authorize_admin(self, token: str, op: str) -> Decision:
        """Gate for operator actions (restore, checkpoint, validation). Raises ``AccessDenied``."""
        corr = uuid.uuid4().hex
        d = self._decide(token, op, None)
        if not d.allow:
            raise self._deny(d, op, None, corr)
        self._emit(d, op, None, corr, True)
        return d

    # -- crypto helpers ---------------------------------------------------------------------------------------
    def _seal(self, order: PurchaseOrder) -> dict[str, Any]:
        if not self.controls.encrypt:
            return crypto.seal_plain(order.to_bytes())
        key_id = self.keys.latest_key_id(order.tenant)
        return crypto.seal(order.to_bytes(), crypto.record_aad(order.tenant, order.record_id, SCHEMA, order.version),
                           self.keys.public_wrap(key_id), key_id)

    def _open(self, env: dict[str, Any], tenant: str, record_id: str, version: int) -> PurchaseOrder:
        if not self.controls.encrypt:
            plain = crypto.open_plain(env)
        else:
            plain = crypto.open_envelope(env, crypto.record_aad(tenant, record_id, SCHEMA, version), self.keys.private_wrap)
        order = PurchaseOrder.from_bytes(plain)
        if (order.tenant, order.record_id, order.version) != (tenant, record_id, version):
            raise IntegrityError("authenticated identity does not match the requested record")
        return order

    # -- writes -----------------------------------------------------------------------------------------------
    def _commit(self, order: PurchaseOrder, expected_version: int, idem_key: str, corr: str) -> Receipt:
        env = self._seal(order)
        res: CommitResult = self.store.commit_version(order.tenant, order.record_id, expected_version, env, idem_key,
                                                      time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.clock())))
        if res.duplicate:
            existing = self.store.get_version(order.tenant, order.record_id, res.version)
            if existing is None or self._open(existing[1], order.tenant, order.record_id, res.version) != order:
                raise IdempotencyConflict("idempotency key already used for a different write")
            env = existing[1]
        if self.controls.journal:
            self._journal_once(order, res, env)
        return Receipt(order.tenant, order.record_id, res.version, res.txn_id, res.duplicate, corr)

    def _journal_once(self, order: PurchaseOrder, res: CommitResult, env: dict[str, Any]) -> None:
        if res.duplicate and self.journal_has(res.txn_id):
            return
        row = self.store.txn_row(res.txn_id)
        self.journal.append(row, env)

    def journal_has(self, txn_id: int) -> bool:
        if not self.home.journal_path.exists():
            return False
        needle = f'"txn_id":{txn_id},'.encode()
        with self.home.journal_path.open("rb") as fh:
            return any(needle in line for line in fh)

    def create_order(self, token: str, tenant: str, record_id: str, department: str, vendor: str, currency: str,
                     amount_minor: int, status: str = "draft", idem_key: str | None = None) -> Receipt:
        corr = uuid.uuid4().hex
        order = PurchaseOrder(record_id, tenant, department, vendor, currency, amount_minor, 1, status)
        d = self._require(token, "create_order", tenant, department, corr)
        self._emit(d, "create_order", tenant, corr, True)
        return self._commit(order, 0, idem_key or uuid.uuid4().hex, corr)

    def update_order(self, token: str, tenant: str, record_id: str, changes: dict[str, Any], expected_version: int,
                     idem_key: str | None = None) -> Receipt:
        corr = uuid.uuid4().hex
        d = self._require(token, "update_order", tenant, None, corr)
        row = self.store.get_current(tenant, record_id)
        if row is None:
            raise self._deny(d, "update_order", tenant, corr)
        current = self._open(row[2], tenant, record_id, row[0])
        if "*" not in d.departments and current.department not in d.departments:
            raise self._deny(d, "update_order", tenant, corr)
        key = idem_key or uuid.uuid4().hex
        if current.version != expected_version:
            # still allow an idempotent replay of an earlier successful update
            updated = replace_checked(current, changes, expected_version)
            self._emit(d, "update_order", tenant, corr, True)
            return self._commit(updated, expected_version, key, corr)
        updated = current.with_changes(**changes)
        if "*" not in d.departments and updated.department not in d.departments:
            raise self._deny(d, "update_order", tenant, corr)
        self._emit(d, "update_order", tenant, corr, True)
        return self._commit(updated, expected_version, key, corr)

    # -- reads ------------------------------------------------------------------------------------------------
    def read_order(self, token: str, tenant: str, record_id: str) -> PurchaseOrder:
        corr = uuid.uuid4().hex
        d = self._require(token, "read_order", tenant, None, corr)
        row = self.store.get_current(tenant, record_id)
        if row is None:
            raise self._deny(d, "read_order", tenant, corr)
        order = self._open(row[2], tenant, record_id, row[0])
        if "*" not in d.departments and order.department not in d.departments:
            raise self._deny(d, "read_order", tenant, corr)
        self._emit(d, "read_order", tenant, corr, True)
        return order

    def _report(self, tenant: str, department: str) -> SpendingReport:
        last_txn = self.store.last_txn()[0]
        rows = [(self._open(env, tenant, rid, ver), txn) for rid, ver, txn, env in self.store.current_rows(tenant)]
        return build_report(tenant, department, rows, last_txn)

    def spending_report(self, token: str, tenant: str, department: str) -> SpendingReport:
        corr = uuid.uuid4().hex
        d = self._require(token, "spending_report", tenant, department, corr)
        report = self._report(tenant, department)
        self._emit(d, "spending_report", tenant, corr, True)
        return report

    def export_report(self, token: str, tenant: str, department: str) -> bytes:
        corr = uuid.uuid4().hex
        d = self._require(token, "export_report", tenant, department, corr)
        report = self._report(tenant, department)
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(["record_id", "version", "txn_id", "amount_minor", "currency"])
        for c in report.contributions:
            w.writerow([c.record_id, c.version, c.txn_id, c.amount_minor, c.currency])
        self._emit(d, "export_report", tenant, corr, True)
        return buf.getvalue().encode("utf-8")

    def verify_report(self, token: str, report: SpendingReport) -> VerifyResult:
        """Check a report's totals against the committed transactions it cites (same permission as the report)."""
        corr = uuid.uuid4().hex
        d = self._require(token, "spending_report", report.tenant, report.department, corr)
        problems: list[str] = []
        present = self.store.txns_present(report.txn_ids)
        totals: dict[str, int] = {}
        for c in report.contributions:
            if c.txn_id not in present:
                problems.append(f"txn {c.txn_id} is not committed")
                continue
            if self.store.txn_lookup(c.txn_id) != (report.tenant, c.record_id, c.version):
                problems.append(f"txn {c.txn_id} does not commit {c.record_id}@{c.version}")
                continue
            got = self.store.get_version(report.tenant, c.record_id, c.version)
            order = self._open(got[1], report.tenant, c.record_id, c.version) if got else None
            if order is None or order.amount_minor != c.amount_minor or order.currency != c.currency:
                problems.append(f"{c.record_id}@{c.version} does not match its committed value")
                continue
            totals[c.currency] = totals.get(c.currency, 0) + order.amount_minor
        if totals != report.totals_by_currency and not problems:
            problems.append("report totals do not equal the sum of committed contributions")
        self._emit(d, "spending_report", report.tenant, corr, True)
        return VerifyResult(not problems, tuple(problems))

    # -- operator ---------------------------------------------------------------------------------------------
    def validate_restore(self, token: str) -> StoreVerification:
        """Recovery operator check: structural and cryptographic verification, no business values returned."""
        self.authorize_admin(token, "validate_restore")
        return verify_store(self.store, self.keys)

    def health(self) -> dict[str, Any]:
        """Unauthenticated local liveness: can the store be opened and read?"""
        try:
            txn_id, _ = self.store.last_txn()
            return {"ok": True, "last_txn_id": txn_id}
        except StoreUnavailable as exc:
            return {"ok": False, "reason": type(exc).__name__}


def replace_checked(current: PurchaseOrder, changes: dict[str, Any], expected_version: int) -> PurchaseOrder:
    """Rebuild the version an older client expected so an idempotent retry can be recognised by the store.

    If the store's idempotency key matches, the original receipt is returned. If it does not, the store's
    optimistic check raises ``ConcurrencyError`` with the real current version.
    """
    if expected_version < 1 or expected_version > current.version:
        raise ValidationError("expected_version is not a version of this record")
    return PurchaseOrder(current.record_id, current.tenant, changes.get("department", current.department),
                         changes.get("vendor", current.vendor), changes.get("currency", current.currency),
                         changes.get("amount_minor", current.amount_minor), expected_version + 1,
                         changes.get("status", current.status))
