"""On-disk layout of a MIS home and its one-time provisioning.

``keys/``     private material (wrapping + signing keys)         never in a backup, the database, logs or Git
``trust/``    public verification/wrapping keys, anchor, approved-checkpoint chain (outside the recoverable data)
``policy/``   current access policy and sessions (never restored from a snapshot)
``data/``     the business store that snapshots capture and recovery replaces
``journal/``  signed write-ahead journal      ``backups/`` encrypted snapshots      ``staging/`` restore workspace
``probes/``   independent business-probe records and ledger (outside the store being restored)
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from resilient_mis.errors import MisError
from resilient_mis.keys import KeyStore
from resilient_mis.policy import PolicyStore
from resilient_mis.store import Store

FIXTURE_MARKER = ".mis-fixture"


@dataclass(frozen=True)
class Home:
    root: Path

    @property
    def keys(self) -> Path:
        return self.root / "keys"

    @property
    def trust(self) -> Path:
        return self.root / "trust"

    @property
    def store_path(self) -> Path:
        return self.root / "data" / "store.db"

    @property
    def policy_path(self) -> Path:
        return self.root / "policy" / "policy.db"

    @property
    def journal_path(self) -> Path:
        return self.root / "journal" / "journal.jsonl"

    @property
    def telemetry_path(self) -> Path:
        return self.root / "telemetry" / "events.jsonl"

    @property
    def backups(self) -> Path:
        return self.root / "backups"

    @property
    def staging(self) -> Path:
        return self.root / "staging"

    @property
    def probes(self) -> Path:
        return self.root / "probes"

    @property
    def is_disposable_fixture(self) -> bool:
        return (self.root / FIXTURE_MARKER).exists()


def as_home(h: Home | str | Path) -> Home:
    return h if isinstance(h, Home) else Home(Path(h))


def init_home(root: Path | str, cfg: dict[str, Any], disposable: bool = False, keys_from: Path | str | None = None) -> Home:
    """Create keys, empty store and policy database. Refuses to touch an already provisioned home.

    ``keys_from`` copies the key material of an existing DISPOSABLE fixture home (benchmark/trial speed-up only); the approved
    checkpoint chain and sequence counter are never copied.
    """
    home = Home(Path(root))
    if (home.keys / "index.json").exists() or home.store_path.exists():
        raise MisError("home is already provisioned; refusing to overwrite")
    home.root.mkdir(parents=True, exist_ok=True)
    for d in (home.backups, home.staging, home.probes, home.journal_path.parent, home.telemetry_path.parent):
        d.mkdir(parents=True, exist_ok=True)
    if keys_from is None:
        KeyStore.create(home.root, list(cfg["tenants"]), rsa_bits=int(cfg["rsa_bits"]))
    else:
        src = Home(Path(keys_from))
        if not src.is_disposable_fixture:
            raise MisError("keys can only be cloned from a disposable fixture home")
        shutil.copytree(src.keys, home.keys)
        shutil.copytree(src.trust, home.trust, ignore=shutil.ignore_patterns("checkpoints.jsonl", "sequence"))
    Store(home.store_path).init_schema(list(cfg["tenants"]))
    PolicyStore(home.policy_path)
    (home.root / "home.json").write_text(json.dumps({"tenants": cfg["tenants"], "rsa_bits": cfg["rsa_bits"]}, indent=2), encoding="utf-8")
    if disposable:
        (home.root / FIXTURE_MARKER).write_text("disposable fixture: fault injection permitted\n", encoding="utf-8")
    return home
