"""Disposable fixture homes populated with INVENTED two-tenant purchase orders (used by the walkthrough, trials and tests)."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from resilient_mis.config import load_config
from resilient_mis.layout import Home, init_home
from resilient_mis.probes import Ledger, LedgerClient, ProbeSpec
from resilient_mis.service import Controls, MisService

VENDORS = ("Northwind Supply", "Contoso Parts", "Fabrikam Tools", "Tailspin Freight", "Adventure Works", "Litware Office")


@dataclass
class Fixture:
    home: Home
    svc: MisService
    ledger: Ledger
    client: LedgerClient
    tokens: dict[str, str]
    cfg: dict[str, Any]

    def spec(self, tenant: str = "tenant-a", department: str = "ops", revoked: bool = True) -> ProbeSpec:
        return ProbeSpec(tenant, department, self.tokens["manager_a"], self.tokens["analyst_a"] if revoked else None, self.ledger)


def provision_identities(svc: MisService) -> dict[str, str]:
    p = svc.policy
    p.grant("mgr-a", "manager", "tenant-a", ["ops", "research", "zz-probe"], ["reporting", "procurement"])
    p.grant("analyst-a", "analyst", "tenant-a", ["ops"], ["reporting"])
    p.grant("mgr-b", "manager", "tenant-b", ["ops"], ["reporting"])
    p.grant("recovery-op", "recovery_operator", "tenant-a", [], ["operations"])
    for dev in ("dev-mgr-a", "dev-analyst-a", "dev-mgr-b", "dev-recovery"):
        p.set_device_trust(dev, True)
    s = svc.sessions
    return {"manager_a": s.login("mgr-a", "dev-mgr-a", "reporting"), "analyst_a": s.login("analyst-a", "dev-analyst-a", "reporting"),
            "manager_b": s.login("mgr-b", "dev-mgr-b", "reporting"), "recovery": s.login("recovery-op", "dev-recovery", "operations")}


def populate(fx_client: LedgerClient, tokens: dict[str, str], n_ops: int, seed: int) -> None:
    """Different orders per tenant. Amounts are integer minor units; a few orders stay draft/rejected and so are not spend."""
    rng = np.random.default_rng(seed)
    statuses = ["approved", "approved", "approved", "draft", "rejected"]
    for i in range(1, n_ops + 1):
        fx_client.create(tokens["manager_a"], "tenant-a", f"PO-{i:06d}", "ops", VENDORS[i % len(VENDORS)], "USD", int(rng.integers(5_000, 900_000)),
                         statuses[i % len(statuses)], idem_key=f"seed-a-ops-{i}")
    for i in range(1, max(3, n_ops // 3) + 1):
        fx_client.create(tokens["manager_a"], "tenant-a", f"PO-R{i:05d}", "research", VENDORS[(i + 2) % len(VENDORS)], "USD",
                         int(rng.integers(5_000, 400_000)), "approved", idem_key=f"seed-a-res-{i}")
    for i in range(1, max(4, n_ops // 2) + 1):
        fx_client.create(tokens["manager_b"], "tenant-b", f"PO-{i:06d}", "ops", VENDORS[(i + 4) % len(VENDORS)], "EUR",
                         int(rng.integers(5_000, 700_000)), "approved", idem_key=f"seed-b-ops-{i}")


def build_fixture(root: Path | str, cfg: dict[str, Any] | None = None, n_orders: int = 12, seed: int = 7, keys_from: Path | str | None = None,
                  controls: Controls | None = None, bench_only: bool = False, with_data: bool = True) -> Fixture:
    cfg = cfg or load_config()
    home = init_home(root, cfg, disposable=True, keys_from=keys_from)
    svc = MisService(home, cfg, controls=controls, _bench_only=bench_only)
    tokens = provision_identities(svc)
    ledger = Ledger(home.probes / "ledger.jsonl")
    client = LedgerClient(svc, ledger)
    if with_data:
        populate(client, tokens, n_orders, seed)
    return Fixture(home, svc, ledger, client, tokens, cfg)


def inject_fault(home: Home, kind: str) -> str:
    """Damage the local store of a DISPOSABLE fixture only. Refuses any other home."""
    if not home.is_disposable_fixture:
        raise PermissionError("fault injection is restricted to disposable fixture homes (no .mis-fixture marker)")
    if kind not in ("delete", "corrupt"):
        raise ValueError("fault kind must be 'delete' or 'corrupt'")
    p = home.store_path
    for attempt in range(100):  # on Windows a concurrent reader (probe, antivirus) can briefly hold the file open
        try:
            if kind == "delete":
                p.unlink()
            else:
                size = max(p.stat().st_size, 4096)
                p.write_bytes(b"\x00corrupted-by-fixture-fault\x00" * (size // 27 + 1))
            break
        except PermissionError:
            if attempt == 99:
                raise
            time.sleep(0.05)
    return kind


def wait_until(pred, timeout_s: float, step_s: float = 0.02) -> bool:
    end = time.monotonic() + timeout_s
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(step_s)
    return pred()
