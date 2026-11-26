"""Authenticated business probes that run as an independent client.

The probe never trusts the service's own view of what the data should be. Expected values come from a ledger of writes the
client saw acknowledged, kept in ``probes/`` OUTSIDE the store being restored. A probe is successful only when the authorised
manager receives the correct report within the deadline. Intentional denials are tested separately and never count as outage.
"""

from __future__ import annotations

import json
import math
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from resilient_mis.errors import AccessDenied, MisError
from resilient_mis.records import SPENT_STATUS
from resilient_mis.service import MisService, Receipt

CANARY_DEPARTMENT = "zz-probe"


class Ledger:
    """Append-only client-side record of acknowledged writes."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, receipt: Receipt, department: str, currency: str, amount_minor: int, status: str, canary: bool = False) -> None:
        row = {"tenant": receipt.tenant, "record_id": receipt.record_id, "version": receipt.version, "txn_id": receipt.txn_id,
               "department": department, "currency": currency, "amount_minor": amount_minor, "status": status, "canary": canary}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True) + "\n")

    def rows(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def expected(self, tenant: str, department: str, up_to_txn: int | None = None) -> dict[str, Any]:
        """Totals the report must show, folded from acknowledged writes (optionally only those the restored chain contains)."""
        latest: dict[str, dict[str, Any]] = {}
        for r in self.rows():
            if r["tenant"] != tenant or (up_to_txn is not None and r["txn_id"] > up_to_txn):
                continue
            if r["record_id"] not in latest or r["version"] > latest[r["record_id"]]["version"]:
                latest[r["record_id"]] = r
        totals: dict[str, int] = {}
        count = 0
        for r in latest.values():
            if r["department"] == department and r["status"] == SPENT_STATUS:
                totals[r["currency"]] = totals.get(r["currency"], 0) + r["amount_minor"]
                count += 1
        return {"totals_by_currency": dict(sorted(totals.items())), "order_count": count}

    def lost_after(self, restored_last_txn: int) -> list[dict[str, Any]]:
        """Acknowledged (non-canary) writes that the restored history does not contain."""
        return [r for r in self.rows() if not r["canary"] and r["txn_id"] > restored_last_txn]


class LedgerClient:
    """Thin client: performs writes through the service and records only acknowledged ones."""

    def __init__(self, svc: MisService, ledger: Ledger) -> None:
        self.svc, self.ledger = svc, ledger

    def create(self, token: str, tenant: str, record_id: str, department: str, vendor: str, currency: str, amount_minor: int,
               status: str = "approved", idem_key: str | None = None, canary: bool = False) -> Receipt:
        r = self.svc.create_order(token, tenant, record_id, department, vendor, currency, amount_minor, status, idem_key)
        self.ledger.record(r, department, currency, amount_minor, status, canary)
        return r

    def update(self, token: str, tenant: str, record_id: str, changes: dict[str, Any], expected_version: int, idem_key: str | None = None) -> Receipt:
        cur = self.svc.read_order(token, tenant, record_id)
        r = self.svc.update_order(token, tenant, record_id, changes, expected_version, idem_key)
        new = cur.with_changes(**changes)
        self.ledger.record(r, new.department, new.currency, new.amount_minor, new.status)
        return r


@dataclass
class ProbeSpec:
    tenant: str
    department: str
    manager_token: str
    revoked_token: str | None
    ledger: Ledger
    up_to_txn: int | None = None
    known_record_id: str = "PO-000001"


@dataclass
class ProbeOutcome:
    ok: bool
    latency_s: float
    reason: str
    checks: dict[str, bool] = field(default_factory=dict)


def report_probe(svc: MisService, spec: ProbeSpec, deadline_s: float) -> ProbeOutcome:
    """Availability probe: authorised read returns the expected report within the deadline."""
    t = time.monotonic()
    try:
        rep = svc.spending_report(spec.manager_token, spec.tenant, spec.department)
    except MisError as exc:
        return ProbeOutcome(False, time.monotonic() - t, type(exc).__name__)
    except Exception as exc:  # unreadable store etc.: a failed probe, never a crash of the probe loop
        return ProbeOutcome(False, time.monotonic() - t, type(exc).__name__)
    latency = time.monotonic() - t
    exp = spec.ledger.expected(spec.tenant, spec.department, spec.up_to_txn)
    if rep.totals_by_currency != exp["totals_by_currency"] or rep.order_count != exp["order_count"]:
        return ProbeOutcome(False, latency, "wrong_report")
    if latency > deadline_s:
        return ProbeOutcome(False, latency, "deadline_exceeded")
    return ProbeOutcome(True, latency, "ok")


def readiness_probe(svc: MisService, spec: ProbeSpec, canary_token: str, deadline_s: float = 5.0) -> ProbeOutcome:
    """Recovery-complete criterion: correct report for the manager, revoked analyst still denied, and a new valid write commits."""
    t = time.monotonic()
    checks: dict[str, bool] = {}
    checks["manager_report_correct"] = report_probe(svc, spec, deadline_s).ok
    if spec.revoked_token is None:
        checks["revoked_access_still_denied"] = True
    else:
        try:
            svc.read_order(spec.revoked_token, spec.tenant, spec.known_record_id)
            checks["revoked_access_still_denied"] = False
        except AccessDenied:
            checks["revoked_access_still_denied"] = True
        except MisError:
            checks["revoked_access_still_denied"] = False
    try:
        rid = f"CANARY-{int(time.time() * 1000)}"
        LedgerClient(svc, spec.ledger).create(canary_token, spec.tenant, rid, CANARY_DEPARTMENT, "Probe", "USD", 1, "draft", canary=True)
        checks["new_write_commits"] = True
    except Exception:
        checks["new_write_commits"] = False
    ok = all(checks.values())
    return ProbeOutcome(ok, time.monotonic() - t, "ok" if ok else "failed:" + ",".join(k for k, v in checks.items() if not v), checks)


class ProbeRunner:
    """Scheduled probes on a monotonic grid; records are persisted outside the store when the runner stops."""

    def __init__(self, svc: MisService, spec: ProbeSpec, cadence_s: float, deadline_s: float, out_path: Path, trial: str) -> None:
        self.svc, self.spec, self.cadence_s, self.deadline_s = svc, spec, cadence_s, deadline_s
        self.out_path, self.trial = Path(out_path), trial
        self.records: list[dict[str, Any]] = []
        self.t0 = 0.0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> float:
        self.t0 = time.monotonic()
        self._thread.start()
        return self.t0

    def _run(self) -> None:
        seq = 0
        while not self._stop.is_set():
            due = self.t0 + seq * self.cadence_s
            wait = due - time.monotonic()
            if wait > 0 and self._stop.wait(wait):
                break
            started = time.monotonic()
            out = report_probe(self.svc, self.spec, self.deadline_s)
            finished = time.monotonic()
            self.records.append({"trial": self.trial, "seq": seq, "scheduled_s": round(seq * self.cadence_s, 6), "started_s": round(started - self.t0, 6),
                                 "finished_s": round(finished - self.t0, 6), "latency_s": round(out.latency_s, 6), "ok": out.ok, "reason": out.reason})
            # slots whose due time passed while this probe was running are NOT back-filled: they stay missing records
            seq = max(seq + 1, math.ceil((finished - self.t0) / self.cadence_s))

    def stop(self) -> list[dict[str, Any]]:
        self._stop.set()
        self._thread.join(timeout=10)
        self.out_path.parent.mkdir(parents=True, exist_ok=True)
        with self.out_path.open("a", encoding="utf-8") as fh:
            for r in self.records:
                fh.write(json.dumps(r, sort_keys=True) + "\n")
        return self.records
