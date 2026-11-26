"""Minimal structured telemetry plus validated import of recorded events.

Emitted fields only: pseudonymous principal, tenant, operation, decision, event time, arrival time, correlation id.
No plaintext, keys, tokens, record ids, amounts or evaluation labels ever appear here.
"""

from __future__ import annotations

import csv
import json
import re
import threading
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from resilient_mis.errors import DataError
from resilient_mis.keys import KeyStore

OPERATIONS = ("read_order", "spending_report", "create_order", "update_order", "export_report", "validate_restore", "restore", "checkpoint")
DECISIONS = ("allow", "deny", "error")
REQUIRED = ("event_time", "arrival_time", "principal", "tenant", "operation", "decision", "correlation_id")
FORBIDDEN_NAME = re.compile(r"(label|ground|truth|incident|scenario|anomal|attack|token|secret|password|plaintext|key|amount|record_id)", re.I)
_LOCK = threading.Lock()


def iso(ts: float | datetime) -> str:
    dt = ts if isinstance(ts, datetime) else datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_ts(value: str) -> datetime:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"not an ISO 8601 timestamp: {value!r}") from exc
    if dt.tzinfo is None:
        raise ValueError(f"timestamp has no UTC offset: {value!r}")
    return dt.astimezone(timezone.utc)


class Telemetry:
    def __init__(self, path: Path, keystore: KeyStore | None, clock: Callable[[], float]) -> None:
        self.path = Path(path)
        self.keystore = keystore
        self.clock = clock
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, principal: str | None, tenant: str | None, operation: str, decision: str, correlation_id: str | None = None) -> str:
        cid = correlation_id or uuid.uuid4().hex
        now = self.clock()
        pseud = self.keystore.pseudonym(principal) if (self.keystore and principal) else "p-anonymous"
        rec = {"event_time": iso(now), "arrival_time": iso(now), "principal": pseud, "tenant": tenant or "-",
               "operation": operation, "decision": decision, "correlation_id": cid}
        with _LOCK, self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
        return cid


def validate_events(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Strict schema check for imported or generated telemetry. Raises ``DataError`` listing every problem."""
    problems: list[str] = []
    if not rows:
        raise DataError("no events found", ["file is empty"])
    cols = set(rows[0].keys())
    missing = [c for c in REQUIRED if c not in cols]
    if missing:
        raise DataError("missing required columns", [f"missing column: {c}" for c in missing])
    banned = sorted(c for c in cols if c not in REQUIRED and FORBIDDEN_NAME.search(c))
    if banned:
        raise DataError("columns that look like labels, secrets or business data are not accepted", [f"forbidden column: {c}" for c in banned])
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for i, r in enumerate(rows, 1):
        row_problems: list[str] = []
        try:
            et, at = parse_ts(str(r["event_time"])), parse_ts(str(r["arrival_time"]))
            if at < et - timedelta(seconds=1):
                row_problems.append("arrival_time precedes event_time")
        except ValueError as exc:
            row_problems.append(str(exc))
            et = at = None
        if r["operation"] not in OPERATIONS:
            row_problems.append(f"unknown operation {r['operation']!r}")
        if r["decision"] not in DECISIONS:
            row_problems.append(f"unknown decision {r['decision']!r}")
        for f in ("principal", "tenant", "correlation_id"):
            if not str(r.get(f) or "").strip():
                row_problems.append(f"empty {f}")
        cid = str(r.get("correlation_id"))
        if cid in seen:
            row_problems.append("duplicate correlation_id")
        seen.add(cid)
        if row_problems:
            problems.extend(f"row {i}: {p}" for p in row_problems)
            continue
        out.append({**{k: r[k] for k in REQUIRED}, "_event_dt": et, "_arrival_dt": at})
    if problems:
        raise DataError(f"{len(problems)} validation problem(s)", problems[:50])
    return out


def load_events(path: Path) -> list[dict[str, Any]]:
    """Load CSV or JSONL (by extension) and validate. Returns events sorted by arrival time (replay order)."""
    path = Path(path)
    try:
        if path.suffix.lower() == ".csv":
            with path.open(newline="", encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
        else:
            rows = []
            with path.open(encoding="utf-8") as fh:
                for n, line in enumerate(fh, 1):
                    if line.strip():
                        try:
                            rows.append(json.loads(line))
                        except ValueError as exc:
                            raise DataError("malformed JSONL", [f"line {n}: not valid JSON"]) from exc
    except OSError as exc:
        raise DataError(f"cannot read {path}", [str(exc)]) from exc
    ok = validate_events(rows)
    return sorted(ok, key=lambda e: (e["_arrival_dt"], e["correlation_id"]))
