"""Current access policy, kept in its own database so restoring business data can never roll it back.

Roles, tenant and department scope, permitted purposes and a trusted-device flag are read FRESH on every decision, so a
revocation or a device-trust change takes effect on the very next call, including for sessions issued earlier.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from resilient_mis.errors import ValidationError

ROLE_OPERATIONS: dict[str, frozenset[str]] = {
    "analyst": frozenset({"read_order", "spending_report"}),
    "manager": frozenset({"read_order", "spending_report", "create_order", "update_order", "export_report"}),
    "recovery_operator": frozenset({"validate_restore", "restore", "checkpoint"}),
}
BUSINESS_OPERATIONS = frozenset({"read_order", "spending_report", "create_order", "update_order", "export_report"})
PURPOSES = ("reporting", "procurement", "audit", "operations")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS principals(principal TEXT PRIMARY KEY, role TEXT NOT NULL, tenant TEXT NOT NULL,
  departments TEXT NOT NULL, purposes TEXT NOT NULL, active INTEGER NOT NULL, updated_epoch INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS devices(device_id TEXT PRIMARY KEY, trusted INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, principal TEXT NOT NULL, device_id TEXT NOT NULL,
  purpose TEXT NOT NULL, issued_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT OR IGNORE INTO meta(key, value) VALUES('epoch', '0');
"""


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str
    principal: str | None = None
    role: str | None = None
    tenant: str | None = None
    departments: tuple[str, ...] = ()


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


class PolicyStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._conn()) as c:
            c.executescript(_SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        c.row_factory = sqlite3.Row
        return c

    def _bump(self, c: sqlite3.Connection) -> int:
        c.execute("UPDATE meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'epoch'")
        return int(c.execute("SELECT value FROM meta WHERE key = 'epoch'").fetchone()[0])

    @property
    def epoch(self) -> int:
        with closing(self._conn()) as c:
            return int(c.execute("SELECT value FROM meta WHERE key = 'epoch'").fetchone()[0])

    # -- administration ---------------------------------------------------------------------------------------
    def grant(self, principal: str, role: str, tenant: str, departments: list[str] | None = None,
              purposes: list[str] | None = None) -> None:
        if role not in ROLE_OPERATIONS:
            raise ValidationError(f"unknown role {role!r}")
        purposes = purposes or ["reporting"]
        bad = [p for p in purposes if p not in PURPOSES]
        if bad:
            raise ValidationError(f"unknown purpose {bad}")
        with closing(self._conn()) as c:
            c.execute("BEGIN IMMEDIATE")
            epoch = self._bump(c)
            c.execute("INSERT INTO principals VALUES(?,?,?,?,?,1,?) ON CONFLICT(principal) DO UPDATE SET role=excluded.role, "
                      "tenant=excluded.tenant, departments=excluded.departments, purposes=excluded.purposes, active=1, "
                      "updated_epoch=excluded.updated_epoch",
                      (principal, role, tenant, json.dumps(sorted(departments or [])), json.dumps(sorted(purposes)), epoch))
            c.execute("COMMIT")

    def revoke(self, principal: str) -> int:
        """Deactivate the principal and every session it holds. Returns the new policy epoch."""
        with closing(self._conn()) as c:
            c.execute("BEGIN IMMEDIATE")
            epoch = self._bump(c)
            c.execute("UPDATE principals SET active = 0, updated_epoch = ? WHERE principal = ?", (epoch, principal))
            c.execute("UPDATE sessions SET revoked = 1 WHERE principal = ?", (principal,))
            c.execute("COMMIT")
            return epoch

    def set_device_trust(self, device_id: str, trusted: bool) -> int:
        with closing(self._conn()) as c:
            c.execute("BEGIN IMMEDIATE")
            epoch = self._bump(c)
            c.execute("INSERT INTO devices VALUES(?,?) ON CONFLICT(device_id) DO UPDATE SET trusted=excluded.trusted",
                      (device_id, 1 if trusted else 0))
            c.execute("COMMIT")
            return epoch

    def device_trusted(self, device_id: str) -> bool:
        with closing(self._conn()) as c:
            row = c.execute("SELECT trusted FROM devices WHERE device_id = ?", (device_id,)).fetchone()
            return bool(row and row["trusted"])

    def principal_info(self, principal: str) -> sqlite3.Row | None:
        with closing(self._conn()) as c:
            return c.execute("SELECT * FROM principals WHERE principal = ?", (principal,)).fetchone()

    def add_session(self, token: str, principal: str, device_id: str, purpose: str, issued: float, ttl_s: float) -> None:
        with closing(self._conn()) as c:
            c.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?,0)",
                      (token_hash(token), principal, device_id, purpose, _iso(issued), _iso(issued + ttl_s)))

    # -- decision ---------------------------------------------------------------------------------------------
    def decide(self, token: str, operation: str, tenant: str | None, department: str | None, now: float) -> Decision:
        with closing(self._conn()) as c:
            s = c.execute("SELECT * FROM sessions WHERE token_hash = ?", (token_hash(token or ""),)).fetchone()
            if s is None:
                return Decision(False, "no_session")
            p = c.execute("SELECT * FROM principals WHERE principal = ?", (s["principal"],)).fetchone()
            d = c.execute("SELECT trusted FROM devices WHERE device_id = ?", (s["device_id"],)).fetchone()
        who = s["principal"]
        role = p["role"] if p else None
        if s["revoked"]:
            return Decision(False, "session_revoked", who, role, p["tenant"] if p else None)
        if datetime.fromisoformat(s["expires_at"]).timestamp() <= now:
            return Decision(False, "session_expired", who, role, p["tenant"] if p else None)
        if p is None or not p["active"]:
            return Decision(False, "principal_inactive", who, role, p["tenant"] if p else None)
        t_scope = p["tenant"]
        if operation not in ROLE_OPERATIONS.get(p["role"], frozenset()):
            return Decision(False, "role_denied", who, role, t_scope)
        if not d or not d["trusted"]:
            return Decision(False, "device_untrusted", who, role, t_scope)
        if s["purpose"] not in json.loads(p["purposes"]):
            return Decision(False, "purpose_denied", who, role, t_scope)
        if operation in BUSINESS_OPERATIONS:
            if tenant != t_scope:
                return Decision(False, "tenant_mismatch", who, role, t_scope)
            if department is not None and department not in json.loads(p["departments"]):
                return Decision(False, "department_denied", who, role, t_scope)
        return Decision(True, "ok", who, role, t_scope, tuple(json.loads(p["departments"])))
