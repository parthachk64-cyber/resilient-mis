"""SQLite business store: encrypted record versions plus a hash-chained transaction log.

* Writes run in ``BEGIN IMMEDIATE`` transactions, so concurrent writers serialise; an optimistic ``expected_version``
  turns a lost update into a ``ConcurrencyError`` instead of silent overwrite.
* An idempotency key per write makes retries safe: a retry returns the original receipt and never duplicates an order.
* Every committed transaction chains the previous entry hash, so truncation, reordering or edits are detectable.
* A fence marker file makes the store refuse new work during cutover; ``wait_idle`` drains in-flight operations first.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from resilient_mis.crypto import canonical_json, sha256_hex
from resilient_mis.errors import ConcurrencyError, IdempotencyConflict, IntegrityError, StoreFenced, StoreUnavailable

GENESIS = "0" * 64
SCHEMA_VERSION = "store.v1"

_DDL = """
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE txns(txn_id INTEGER PRIMARY KEY, tenant TEXT NOT NULL, record_id TEXT NOT NULL, version INTEGER NOT NULL,
  idem_key TEXT NOT NULL UNIQUE, committed_at TEXT NOT NULL, env_sha256 TEXT NOT NULL, prev_hash TEXT NOT NULL,
  entry_hash TEXT NOT NULL);
CREATE TABLE records(tenant TEXT NOT NULL, record_id TEXT NOT NULL, version INTEGER NOT NULL,
  txn_id INTEGER NOT NULL REFERENCES txns(txn_id), envelope BLOB NOT NULL, PRIMARY KEY(tenant, record_id, version));
"""


def chain_hash(prev: str, txn_id: int, tenant: str, record_id: str, version: int, idem_key: str, env_sha256: str,
               committed_at: str) -> str:
    return sha256_hex(canonical_json([prev, txn_id, tenant, record_id, version, idem_key, env_sha256, committed_at]))


@dataclass(frozen=True)
class CommitResult:
    txn_id: int
    version: int
    entry_hash: str
    env_sha256: str
    duplicate: bool


class _Gate:
    def __init__(self) -> None:
        self.cond = threading.Condition()
        self.inflight = 0


_GATES: dict[str, _Gate] = {}
_GATES_LOCK = threading.Lock()


def _gate_for(path: Path) -> _Gate:
    key = str(Path(path).resolve())
    with _GATES_LOCK:
        return _GATES.setdefault(key, _Gate())


class Store:
    def __init__(self, path: Path, fence_path: Path | None = None) -> None:
        self.path = Path(path)
        self.fence_path = Path(fence_path) if fence_path else self.path.with_name(self.path.name + ".FENCED")
        self._gate = _gate_for(self.path)

    # -- connection lifecycle ---------------------------------------------------------------------------------
    @contextmanager
    def _open(self, create: bool = False) -> Iterator[sqlite3.Connection]:
        with self._gate.cond:
            if self.fence_path.exists():
                raise StoreFenced("store is fenced for cutover")
            self._gate.inflight += 1
        try:
            if not create and not self.path.exists():
                raise StoreUnavailable("store file is missing")
            try:
                conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA synchronous=FULL")
            except sqlite3.Error as exc:
                raise StoreUnavailable(f"cannot open store: {exc}") from exc
            try:
                yield conn
            except sqlite3.IntegrityError:
                raise
            except sqlite3.DatabaseError as exc:
                raise StoreUnavailable(f"store unreadable: {exc}") from exc
            finally:
                conn.close()
        finally:
            with self._gate.cond:
                self._gate.inflight -= 1
                self._gate.cond.notify_all()

    def fence(self) -> None:
        self.fence_path.parent.mkdir(parents=True, exist_ok=True)
        self.fence_path.write_text("fenced", encoding="utf-8")

    def unfence(self) -> None:
        with suppress(FileNotFoundError):
            self.fence_path.unlink()

    @property
    def is_fenced(self) -> bool:
        return self.fence_path.exists()

    def wait_idle(self, timeout_s: float = 10.0) -> bool:
        with self._gate.cond:
            return self._gate.cond.wait_for(lambda: self._gate.inflight == 0, timeout=timeout_s)

    # -- schema -----------------------------------------------------------------------------------------------
    def init_schema(self, tenants: list[str]) -> None:
        if self.path.exists():
            raise StoreUnavailable("refusing to initialise over an existing store")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._open(create=True) as c:
            c.executescript(_DDL)
            c.executemany("INSERT INTO meta VALUES(?,?)", [("schema_version", SCHEMA_VERSION), ("tenants", json.dumps(sorted(tenants)))])

    def meta(self, key: str) -> str | None:
        with self._open() as c:
            row = c.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
            return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self._open() as c:
            c.execute("INSERT INTO meta VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    # -- writes -----------------------------------------------------------------------------------------------
    def commit_version(self, tenant: str, record_id: str, expected_version: int, envelope: dict[str, Any], idem_key: str,
                       committed_at: str) -> CommitResult:
        env_bytes = canonical_json(envelope)
        env_sha = sha256_hex(env_bytes)
        version = expected_version + 1
        with self._open() as c:
            c.execute("BEGIN IMMEDIATE")
            try:
                dup = c.execute("SELECT * FROM txns WHERE idem_key = ?", (idem_key,)).fetchone()
                if dup is not None:
                    c.execute("ROLLBACK")
                    if (dup["tenant"], dup["record_id"], dup["version"]) != (tenant, record_id, version):
                        raise IdempotencyConflict("idempotency key already used for a different write")
                    return CommitResult(dup["txn_id"], dup["version"], dup["entry_hash"], dup["env_sha256"], True)
                cur = c.execute("SELECT MAX(version) FROM records WHERE tenant=? AND record_id=?", (tenant, record_id)).fetchone()[0] or 0
                if cur != expected_version:
                    c.execute("ROLLBACK")
                    raise ConcurrencyError(f"expected version {expected_version}, current is {cur}", cur)
                last = c.execute("SELECT txn_id, entry_hash FROM txns ORDER BY txn_id DESC LIMIT 1").fetchone()
                txn_id = (last["txn_id"] if last else 0) + 1
                prev = last["entry_hash"] if last else GENESIS
                eh = chain_hash(prev, txn_id, tenant, record_id, version, idem_key, env_sha, committed_at)
                c.execute("INSERT INTO txns VALUES(?,?,?,?,?,?,?,?,?)",
                          (txn_id, tenant, record_id, version, idem_key, committed_at, env_sha, prev, eh))
                c.execute("INSERT INTO records VALUES(?,?,?,?,?)", (tenant, record_id, version, txn_id, env_bytes))
                c.execute("COMMIT")
            except BaseException:
                with suppress(sqlite3.Error):
                    c.execute("ROLLBACK")
                raise
        return CommitResult(txn_id, version, eh, env_sha, False)

    def append_replayed(self, txn_id: int, tenant: str, record_id: str, version: int, idem_key: str, committed_at: str,
                        envelope: dict[str, Any], expected_entry_hash: str) -> str:
        """Re-apply a journalled write into a staging store, recomputing and checking the hash chain."""
        env_bytes = canonical_json(envelope)
        env_sha = sha256_hex(env_bytes)
        with self._open() as c:
            c.execute("BEGIN IMMEDIATE")
            try:
                last = c.execute("SELECT txn_id, entry_hash FROM txns ORDER BY txn_id DESC LIMIT 1").fetchone()
                if txn_id != (last["txn_id"] if last else 0) + 1:
                    raise IntegrityError("journal entry is not the next transaction")
                prev = last["entry_hash"] if last else GENESIS
                eh = chain_hash(prev, txn_id, tenant, record_id, version, idem_key, env_sha, committed_at)
                if eh != expected_entry_hash:
                    raise IntegrityError("journal entry does not extend the restored hash chain")
                cur = c.execute("SELECT MAX(version) FROM records WHERE tenant=? AND record_id=?", (tenant, record_id)).fetchone()[0] or 0
                if version != cur + 1:
                    raise IntegrityError("journal entry has an unexpected record version")
                c.execute("INSERT INTO txns VALUES(?,?,?,?,?,?,?,?,?)",
                          (txn_id, tenant, record_id, version, idem_key, committed_at, env_sha, prev, eh))
                c.execute("INSERT INTO records VALUES(?,?,?,?,?)", (tenant, record_id, version, txn_id, env_bytes))
                c.execute("COMMIT")
            except BaseException:
                with suppress(sqlite3.Error):
                    c.execute("ROLLBACK")
                raise
        return eh

    # -- reads ------------------------------------------------------------------------------------------------
    def current_rows(self, tenant: str) -> list[tuple[str, int, int, dict[str, Any]]]:
        with self._open() as c:
            rows = c.execute(
                "SELECT r.record_id, r.version, r.txn_id, r.envelope FROM records r JOIN (SELECT record_id, MAX(version) v FROM records "
                "WHERE tenant=? GROUP BY record_id) m ON r.record_id=m.record_id AND r.version=m.v WHERE r.tenant=? ORDER BY r.record_id",
                (tenant, tenant)).fetchall()
            return [(r["record_id"], r["version"], r["txn_id"], json.loads(r["envelope"])) for r in rows]

    def get_current(self, tenant: str, record_id: str) -> tuple[int, int, dict[str, Any]] | None:
        with self._open() as c:
            r = c.execute("SELECT version, txn_id, envelope FROM records WHERE tenant=? AND record_id=? ORDER BY version DESC LIMIT 1",
                          (tenant, record_id)).fetchone()
            return None if r is None else (r["version"], r["txn_id"], json.loads(r["envelope"]))

    def get_version(self, tenant: str, record_id: str, version: int) -> tuple[int, dict[str, Any]] | None:
        with self._open() as c:
            r = c.execute("SELECT txn_id, envelope FROM records WHERE tenant=? AND record_id=? AND version=?",
                          (tenant, record_id, version)).fetchone()
            return None if r is None else (r["txn_id"], json.loads(r["envelope"]))

    def all_rows(self) -> list[tuple[str, str, int, int, dict[str, Any]]]:
        with self._open() as c:
            rows = c.execute("SELECT tenant, record_id, version, txn_id, envelope FROM records ORDER BY tenant, record_id, version").fetchall()
            return [(r["tenant"], r["record_id"], r["version"], r["txn_id"], json.loads(r["envelope"])) for r in rows]

    def last_txn(self) -> tuple[int, str]:
        with self._open() as c:
            r = c.execute("SELECT txn_id, entry_hash FROM txns ORDER BY txn_id DESC LIMIT 1").fetchone()
            return (r["txn_id"], r["entry_hash"]) if r else (0, GENESIS)

    def txn_hash_at(self, txn_id: int) -> str | None:
        with self._open() as c:
            r = c.execute("SELECT entry_hash FROM txns WHERE txn_id=?", (txn_id,)).fetchone()
            return r["entry_hash"] if r else None

    def txn_row(self, txn_id: int) -> dict[str, Any]:
        with self._open() as c:
            r = c.execute("SELECT txn_id, tenant, record_id, version, idem_key, committed_at, entry_hash FROM txns WHERE txn_id=?",
                          (txn_id,)).fetchone()
            if r is None:
                raise StoreUnavailable(f"txn {txn_id} not found")
            return dict(r)

    def txns_present(self, ids: list[int]) -> set[int]:
        if not ids:
            return set()
        with self._open() as c:
            q = ",".join("?" for _ in ids)
            return {r[0] for r in c.execute(f"SELECT txn_id FROM txns WHERE txn_id IN ({q})", ids)}

    def txn_lookup(self, txn_id: int) -> tuple[str, str, int] | None:
        with self._open() as c:
            r = c.execute("SELECT tenant, record_id, version FROM txns WHERE txn_id=?", (txn_id,)).fetchone()
            return (r["tenant"], r["record_id"], r["version"]) if r else None

    def count(self) -> dict[str, int]:
        with self._open() as c:
            return {"txns": c.execute("SELECT COUNT(*) FROM txns").fetchone()[0],
                    "record_versions": c.execute("SELECT COUNT(*) FROM records").fetchone()[0],
                    "records": c.execute("SELECT COUNT(*) FROM (SELECT DISTINCT tenant, record_id FROM records)").fetchone()[0]}

    # -- verification & backup --------------------------------------------------------------------------------
    def integrity_check(self) -> bool:
        with self._open() as c:
            return c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"

    def verify_chain(self) -> int:
        """Recompute the whole hash chain; raise ``IntegrityError`` on any break. Returns the number of transactions."""
        with self._open() as c:
            txns = c.execute("SELECT * FROM txns ORDER BY txn_id").fetchall()
            recs = {(r["tenant"], r["record_id"], r["version"]): r["txn_id"] for r in c.execute("SELECT * FROM records")}
        prev, expect_id = GENESIS, 1
        for t in txns:
            if t["txn_id"] != expect_id:
                raise IntegrityError(f"transaction ids are not contiguous at {expect_id}")
            if t["prev_hash"] != prev:
                raise IntegrityError(f"hash chain broken at txn {t['txn_id']}")
            eh = chain_hash(prev, t["txn_id"], t["tenant"], t["record_id"], t["version"], t["idem_key"], t["env_sha256"], t["committed_at"])
            if eh != t["entry_hash"]:
                raise IntegrityError(f"entry hash mismatch at txn {t['txn_id']}")
            if recs.get((t["tenant"], t["record_id"], t["version"])) != t["txn_id"]:
                raise IntegrityError(f"txn {t['txn_id']} has no matching record version")
            prev, expect_id = eh, expect_id + 1
        if len(recs) != len(txns):
            raise IntegrityError("record versions without a transaction")
        return len(txns)

    def backup_to(self, dest: Path) -> None:
        """Transactionally consistent copy via the SQLite online backup API."""
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with self._open() as src:
            dst = sqlite3.connect(dest)
            try:
                src.backup(dst)
            finally:
                dst.close()
