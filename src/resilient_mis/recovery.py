"""Verified restore: stage, verify, replay the signed journal, then switch atomically.

Nothing becomes active until the candidate has passed (1) manifest signature, trust-anchor, digest, scope, staleness and
approval checks, (2) decryption with authenticated identity binding for every record version, (3) hash-chain and
business-digest checks against the signed manifest, and (4) journal verification. If any step fails the last known-good
state, including the corrupt-but-present active store, is left byte for byte untouched.

Access policy lives in its own database and is never part of a snapshot, so restoring business data cannot undo a
revocation or a key-policy change.

Data-loss boundary: with the journal, no acknowledged write is lost unless the journal itself is damaged (then the
restore falls back to the snapshot alone and says so). Without it, every write after the approved checkpoint is lost.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from resilient_mis.errors import IntegrityError, KeyCustodyError, RecoveryError, RecoveryInterrupted, SnapshotError, StoreUnavailable
from resilient_mis.service import MisService
from resilient_mis.snapshots import TrustState, VerifiedSnapshot, decrypt_snapshot, verify_snapshot
from resilient_mis.store import Store
from resilient_mis.verify import verify_store

_PHASES = ("fault_onset", "detected", "restore_start", "manifest_verified", "staging_verified", "journal_replayed", "cutover", "ready")


def file_sha256(path: Path) -> str | None:
    p = Path(path)
    if not p.is_file():
        return None
    return hashlib.sha256(p.read_bytes()).hexdigest()


class PhaseTimer:
    """Monotonic phase marks. Phase names are fixed so every trial is comparable."""

    def __init__(self) -> None:
        self.marks: dict[str, float] = {}

    def mark(self, name: str, at: float | None = None) -> float:
        if name not in _PHASES:
            raise ValueError(f"unknown phase {name!r}")
        self.marks[name] = time.monotonic() if at is None else at
        return self.marks[name]

    def durations(self) -> dict[str, float | None]:
        m = self.marks

        def span(a: str, b: str) -> float | None:
            return round(m[b] - m[a], 6) if a in m and b in m else None

        return {"fault_to_detected_s": span("fault_onset", "detected"), "detected_to_restore_start_s": span("detected", "restore_start"),
                "manifest_verification_s": span("restore_start", "manifest_verified"),
                "decrypt_and_verify_s": span("manifest_verified", "staging_verified"),
                "journal_replay_s": span("staging_verified", "journal_replayed"), "cutover_s": span("journal_replayed", "cutover"),
                "cutover_to_ready_s": span("cutover", "ready"), "restore_start_to_ready_s": span("restore_start", "ready"),
                "fault_to_ready_s": span("fault_onset", "ready")}


@dataclass
class RecoveryReport:
    outcome: str                      # restored | already_restored
    snapshot_id: str
    snapshot_sequence: int
    snapshot_last_txn: int
    restored_last_txn: int
    journal_status: str               # replayed | none | rejected:<why> | disabled
    journal_entries_replayed: int
    journal_last_txn: int | None
    business_digest: str
    active_sha256_before: str | None
    active_sha256_after: str | None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


def _select_candidate(svc: MisService, snapshot: Path | None) -> Path:
    if snapshot is not None:
        return Path(snapshot)
    latest = TrustState(svc.home.trust).latest(svc.keys.verify_key("manifest"))
    if latest is None:
        raise RecoveryError("no approved checkpoint exists; nothing trustworthy to restore from")
    return svc.home.backups / latest["snapshot_id"]


def _replay_journal(svc: MisService, staged: Store, use_journal: bool) -> tuple[str, int, int | None]:
    if not use_journal:
        return "disabled", 0, None
    try:
        entries = svc.journal.verified_entries(svc.home.trust / "journal-verify.pub")
    except IntegrityError as exc:
        return f"rejected:{exc}", 0, None
    if not entries:
        return "none", 0, None
    last_in_journal = entries[-1]["txn"]["txn_id"]
    applied = 0
    for e in entries:
        t = e["txn"]
        if t["txn_id"] <= staged.last_txn()[0]:
            continue
        try:
            staged.append_replayed(t["txn_id"], t["tenant"], t["record_id"], t["version"], t["idem_key"], t["committed_at"],
                                   e["envelope"], t["entry_hash"])
        except IntegrityError as exc:
            return f"rejected:{exc}", applied, last_in_journal
        applied += 1
    return "replayed", applied, last_in_journal


def _switch(active: Path, staging: Path) -> None:
    """Two-step atomic switch; if the second step fails the first is undone."""
    kept: Path | None = None
    if active.exists():
        kept = active.with_name(f"{active.name}.replaced-{int(time.time() * 1000)}")
        _replace(active, kept)
    try:
        _replace(staging, active)
    except OSError as exc:
        if kept is not None:
            _replace(kept, active)
        raise RecoveryError(f"cutover failed and was rolled back: {exc}") from exc


def _replace(src: Path, dst: Path, tries: int = 20) -> None:
    for i in range(tries):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if i == tries - 1:
                raise
            time.sleep(0.05)


def recover(svc: MisService, token: str, *, snapshot: Path | None = None, use_journal: bool = True,
            timer: PhaseTimer | None = None, interrupt_before_cutover: bool = False, allow_stale: bool = False) -> RecoveryReport:
    """Restore the business store. Requires a recovery-operator session. Safe to re-run."""
    timer = timer or PhaseTimer()
    svc.authorize_admin(token, "restore")
    timer.mark("restore_start")
    home, keys = svc.home, svc.keys
    before = file_sha256(home.store_path)
    try:
        cand = _select_candidate(svc, snapshot)
        v: VerifiedSnapshot = verify_snapshot(cand, home.trust, expected_tenants=list(svc.cfg["tenants"]), allow_stale=allow_stale)
    except SnapshotError as exc:
        raise RecoveryError(f"candidate rejected ({exc.reason}); active state left untouched") from exc
    timer.mark("manifest_verified")

    stage_db = home.staging / f"restore-{v.snapshot_id}.db"
    for leftover in (stage_db, stage_db.with_name(stage_db.name + ".FENCED")):
        leftover.unlink(missing_ok=True)
    try:
        decrypt_snapshot(v, keys, stage_db)
    except (SnapshotError, KeyCustodyError) as exc:
        raise RecoveryError(f"snapshot could not be decrypted ({exc}); active state left untouched") from exc
    staged = Store(stage_db, fence_path=stage_db.with_name(stage_db.name + ".FENCED"))
    sv = verify_store(staged, keys)
    m = v.manifest
    if not sv.ok:
        raise RecoveryError(f"restored copy failed verification: {sv.problems}; active state left untouched")
    if (sv.last_txn_id, sv.last_txn_hash, sv.business_digest) != (m["last_txn_id"], m["last_txn_hash"], m["business_digest"]):
        raise RecoveryError("restored copy does not match the signed manifest; active state left untouched")
    timer.mark("staging_verified")

    journal_status, applied, journal_last = _replay_journal(svc, staged, use_journal)
    if applied:
        sv = verify_store(staged, keys)
        if not sv.ok:
            raise RecoveryError(f"journal replay produced an unverifiable store: {sv.problems}; active state left untouched")
    staged.set_meta("restored_from", v.snapshot_id)
    timer.mark("journal_replayed")
    notes: list[str] = []
    if journal_status.startswith("rejected"):
        notes.append("journal rejected: restored from snapshot only, writes after the checkpoint are lost")

    if interrupt_before_cutover:
        raise RecoveryInterrupted("interrupted before cutover (fault injection); active state untouched, staging retained")

    outcome = "restored"
    active_ok = False
    try:
        active_ok = verify_store(svc.store, keys).ok
    except StoreUnavailable:
        active_ok = False
    if active_ok:
        tip = svc.store.txn_hash_at(sv.last_txn_id)
        if tip == sv.last_txn_hash:
            outcome = "already_restored"
            notes.append("active store already contains the restored history; nothing replaced, later writes preserved")
        else:
            raise RecoveryError("active store is healthy but diverges from the restore candidate; refusing to replace it")
    if outcome == "restored":
        svc.store.fence()
        try:
            svc.store.wait_idle(10.0)
            _switch(home.store_path, stage_db)
        finally:
            svc.store.unfence()
    else:
        stage_db.unlink(missing_ok=True)
    timer.mark("cutover")
    return RecoveryReport(outcome, v.snapshot_id, m["sequence"], m["last_txn_id"], sv.last_txn_id, journal_status, applied, journal_last,
                          sv.business_digest, before, file_sha256(home.store_path), notes)
