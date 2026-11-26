"""Purchase-order records and the deterministic departmental spending report.

Amounts are integer minor units (e.g. cents). Records are immutable; an update produces a new version.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, replace
from typing import Any

from resilient_mis.crypto import canonical_json, sha256_hex
from resilient_mis.errors import ValidationError

SCHEMA = "po.v1"
STATUSES = ("draft", "approved", "rejected", "cancelled")
SPENT_STATUS = "approved"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,39}$")
_CUR = re.compile(r"^[A-Z]{3}$")
_TEXT = re.compile(r"^[A-Za-z0-9 ._&-]{1,60}$")


@dataclass(frozen=True)
class PurchaseOrder:
    record_id: str
    tenant: str
    department: str
    vendor: str
    currency: str
    amount_minor: int
    version: int
    status: str

    def __post_init__(self) -> None:
        for name in ("record_id", "tenant"):
            if not isinstance(getattr(self, name), str) or not _ID.match(getattr(self, name)):
                raise ValidationError(f"invalid {name}")
        for name in ("department", "vendor"):
            if not isinstance(getattr(self, name), str) or not _TEXT.match(getattr(self, name)):
                raise ValidationError(f"invalid {name}")
        if not isinstance(self.currency, str) or not _CUR.match(self.currency):
            raise ValidationError("currency must be a 3-letter upper-case code")
        if isinstance(self.amount_minor, bool) or not isinstance(self.amount_minor, int) or self.amount_minor < 0:
            raise ValidationError("amount_minor must be a non-negative integer (minor units)")
        if self.amount_minor > 10**13:
            raise ValidationError("amount_minor out of range")
        if isinstance(self.version, bool) or not isinstance(self.version, int) or self.version < 1:
            raise ValidationError("version must be a positive integer")
        if self.status not in STATUSES:
            raise ValidationError(f"status must be one of {STATUSES}")

    def to_bytes(self) -> bytes:
        return canonical_json(asdict(self))

    @classmethod
    def from_bytes(cls, raw: bytes) -> PurchaseOrder:
        try:
            d = json.loads(raw.decode("utf-8"))
            return cls(**d)
        except (ValueError, TypeError) as exc:
            raise ValidationError("record payload does not match the schema") from exc

    def with_changes(self, **changes: Any) -> PurchaseOrder:
        """New object; the original is never mutated. Identity fields cannot change."""
        for forbidden in ("record_id", "tenant", "version"):
            if forbidden in changes:
                raise ValidationError(f"{forbidden} cannot be changed by an update")
        return replace(self, version=self.version + 1, **changes)


@dataclass(frozen=True)
class Contribution:
    record_id: str
    version: int
    txn_id: int
    amount_minor: int
    currency: str


@dataclass(frozen=True)
class SpendingReport:
    tenant: str
    department: str
    totals_by_currency: dict[str, int]
    order_count: int
    contributions: tuple[Contribution, ...]
    as_of_txn: int

    @property
    def txn_ids(self) -> list[int]:
        return sorted(c.txn_id for c in self.contributions)

    def to_dict(self) -> dict[str, Any]:
        return {"tenant": self.tenant, "department": self.department, "totals_by_currency": dict(sorted(self.totals_by_currency.items())),
                "order_count": self.order_count, "as_of_txn": self.as_of_txn,
                "contributions": [asdict(c) for c in self.contributions]}

    def digest(self) -> str:
        return sha256_hex(canonical_json(self.to_dict()))


def build_report(tenant: str, department: str, rows: list[tuple[PurchaseOrder, int]], as_of_txn: int) -> SpendingReport:
    """Deterministic: sorted by record id; only approved orders in the department count as spend."""
    contribs: list[Contribution] = []
    totals: dict[str, int] = {}
    for order, txn_id in sorted(rows, key=lambda r: r[0].record_id):
        if order.tenant != tenant or order.department != department or order.status != SPENT_STATUS:
            continue
        contribs.append(Contribution(order.record_id, order.version, txn_id, order.amount_minor, order.currency))
        totals[order.currency] = totals.get(order.currency, 0) + order.amount_minor
    return SpendingReport(tenant, department, totals, len(contribs), tuple(contribs), as_of_txn)


def business_digest(rows: list[PurchaseOrder]) -> str:
    """Digest of the current business state (tenant, id, version, dept, currency, amount, status), order independent."""
    items = sorted((o.tenant, o.record_id, o.version, o.department, o.currency, o.amount_minor, o.status) for o in rows)
    return sha256_hex(canonical_json(items))
