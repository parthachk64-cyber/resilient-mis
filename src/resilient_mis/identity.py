"""Controlled local session provider.

Identity and context (device, purpose) come from this provider, never from request parameters. Tokens are 256-bit random
values returned to the caller once; only their SHA-256 is stored and they are never written to telemetry or logs.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable

from resilient_mis.errors import AccessDenied
from resilient_mis.policy import PolicyStore


class SessionProvider:
    def __init__(self, policy: PolicyStore, ttl_s: float = 3600.0, clock: Callable[[], float] = time.time) -> None:
        self.policy = policy
        self.ttl_s = ttl_s
        self.clock = clock

    def login(self, principal: str, device_id: str, purpose: str) -> str:
        """Issue a session if the principal is active. Device trust is NOT checked here but on every operation,
        so changing it affects sessions that already exist."""
        info = self.policy.principal_info(principal)
        if info is None or not info["active"]:
            raise AccessDenied("login refused")
        token = secrets.token_urlsafe(32)
        self.policy.add_session(token, principal, device_id, purpose, self.clock(), self.ttl_s)
        return token
