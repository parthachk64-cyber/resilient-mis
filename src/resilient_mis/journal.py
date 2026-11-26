"""Signed, hash-chained write-ahead journal kept OUTSIDE the business store.

Order of operations for an acknowledged write: commit to the store, append + fsync the journal entry, then acknowledge.
A crash between commit and journal loses only an unacknowledged write (documented data-loss boundary). Replay verifies
the Ed25519 signature of every entry, the journal hash chain, and that each entry extends the restored store's own hash
chain, so a tampered or reordered journal cannot be applied.
"""

from __future__ import annotations

import base64
import json
import os
import threading
from pathlib import Path
from typing import Any

from resilient_mis.crypto import canonical_json, sha256_hex
from resilient_mis.errors import IntegrityError
from resilient_mis.keys import KeyStore, load_verify_key, verify_signature

JOURNAL_GENESIS = "0" * 64
_LOCK = threading.Lock()


def _entry_hash(body: dict[str, Any], prev: str) -> str:
    return sha256_hex(canonical_json([prev, body]))


class Journal:
    def __init__(self, path: Path, keystore: KeyStore | None = None) -> None:
        self.path = Path(path)
        self.keystore = keystore
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _tail(self) -> tuple[int, str]:
        if not self.path.exists():
            return 0, JOURNAL_GENESIS
        last = None
        with self.path.open("rb") as fh:
            for line in fh:
                if line.strip():
                    last = line
        if last is None:
            return 0, JOURNAL_GENESIS
        d = json.loads(last)
        return d["seq"], d["hash"]

    def append(self, txn: dict[str, Any], envelope: dict[str, Any]) -> int:
        """``txn`` carries txn_id, tenant, record_id, version, idem_key, committed_at, entry_hash."""
        if self.keystore is None:
            raise IntegrityError("journal opened read-only")
        with _LOCK:
            seq, prev = self._tail()
            body = {"seq": seq + 1, "txn": txn, "envelope": envelope}
            h = _entry_hash(body, prev)
            sig = base64.b64encode(self.keystore.sign("journal", h.encode("ascii"))).decode("ascii")
            line = json.dumps({**body, "prev": prev, "hash": h, "sig": sig}, sort_keys=True, separators=(",", ":"))
            with self.path.open("ab") as fh:
                fh.write(line.encode("utf-8") + b"\n")
                fh.flush()
                os.fsync(fh.fileno())
            return seq + 1

    def verified_entries(self, verify_key_path: Path) -> list[dict[str, Any]]:
        """Return all entries after verifying signatures and chain. Raises ``IntegrityError`` on the first defect."""
        if not self.path.exists():
            return []
        pub = load_verify_key(verify_key_path)
        out: list[dict[str, Any]] = []
        prev, expect = JOURNAL_GENESIS, 1
        with self.path.open("rb") as fh:
            for n, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                try:
                    d = json.loads(line)
                    body = {"seq": d["seq"], "txn": d["txn"], "envelope": d["envelope"]}
                    sig = base64.b64decode(d["sig"], validate=True)
                except (ValueError, KeyError, TypeError) as exc:
                    raise IntegrityError(f"journal line {n} is malformed") from exc
                if d["seq"] != expect or d["prev"] != prev:
                    raise IntegrityError(f"journal chain broken at line {n}")
                h = _entry_hash(body, prev)
                if h != d["hash"] or not verify_signature(pub, sig, h.encode("ascii")):
                    raise IntegrityError(f"journal signature or hash invalid at line {n}")
                out.append(d)
                prev, expect = h, expect + 1
        return out
