"""Store verification shared by recovery and the recovery-operator validation call.

Checks completeness (chain and record/txn agreement), decryptability with authenticated identity binding, contiguous
record versions and business invariants. It deliberately returns counts, booleans and a digest, never business values.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from resilient_mis.crypto import open_envelope, record_aad
from resilient_mis.errors import IntegrityError, KeyCustodyError, ValidationError
from resilient_mis.keys import KeyStore
from resilient_mis.records import SCHEMA, PurchaseOrder, business_digest
from resilient_mis.store import Store


@dataclass
class StoreVerification:
    ok: bool
    txns: int = 0
    record_versions: int = 0
    decrypted: int = 0
    last_txn_id: int = 0
    last_txn_hash: str = ""
    business_digest: str = ""
    problems: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"ok": self.ok, "txns": self.txns, "record_versions": self.record_versions, "decrypted": self.decrypted,
                "last_txn_id": self.last_txn_id, "problems": list(self.problems)}


def verify_store(store: Store, keys: KeyStore) -> StoreVerification:
    res = StoreVerification(ok=False)
    try:
        if not store.integrity_check():
            res.problems.append("sqlite integrity_check failed")
            return res
        res.txns = store.verify_chain()
        res.last_txn_id, res.last_txn_hash = store.last_txn()
        rows = store.all_rows()
        res.record_versions = len(rows)
        latest: dict[tuple[str, str], PurchaseOrder] = {}
        expected_version: dict[tuple[str, str], int] = {}
        for tenant, rid, version, _txn, env in rows:
            if version != expected_version.get((tenant, rid), 0) + 1:
                raise IntegrityError(f"versions of {tenant}/{rid} are not contiguous")
            expected_version[(tenant, rid)] = version
            plain = open_envelope(env, record_aad(tenant, rid, SCHEMA, version), keys.private_wrap)
            order = PurchaseOrder.from_bytes(plain)
            if (order.tenant, order.record_id, order.version) != (tenant, rid, version):
                raise IntegrityError(f"authenticated identity does not match row {tenant}/{rid}@{version}")
            res.decrypted += 1
            latest[(tenant, rid)] = order
        res.business_digest = business_digest(list(latest.values()))
        res.ok = True
    except (IntegrityError, KeyCustodyError, ValidationError) as exc:
        res.problems.append(f"{type(exc).__name__}: {exc}")
    except Exception as exc:  # unreadable store, locked file: report, never crash the caller
        res.problems.append(f"{type(exc).__name__}: {exc}")
    return res
