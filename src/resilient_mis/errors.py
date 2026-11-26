"""Exception hierarchy. External messages are deliberately uniform for denied and missing records."""

from __future__ import annotations


class MisError(Exception):
    """Base class for all companion errors."""


class AccessDenied(MisError):
    """Request refused or record not available. One message for both so callers cannot enumerate records."""

    def __init__(self, message: str = "access denied or record not available") -> None:
        super().__init__(message)


class ValidationError(MisError):
    """Input failed schema or business validation."""


class ConcurrencyError(MisError):
    """Optimistic concurrency check failed (stale expected version)."""

    def __init__(self, message: str, current_version: int = 0) -> None:
        super().__init__(message)
        self.current_version = current_version


class IdempotencyConflict(MisError):
    """An idempotency key was reused for a different write."""


class IntegrityError(MisError):
    """Authenticity or integrity check failed (tag, signature, digest, hash chain, identity binding)."""


class StoreUnavailable(MisError):
    """The business store cannot be opened (missing, corrupt or locked)."""


class StoreFenced(StoreUnavailable):
    """Reads and writes are refused while a cutover is in progress."""


class KeyCustodyError(MisError):
    """A key is missing, malformed or the passphrase is wrong."""


class SnapshotError(MisError):
    """Snapshot or manifest rejected. ``reason`` is a stable machine-readable code."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(f"{reason}: {message}")
        self.reason = reason


class RecoveryError(MisError):
    """Recovery refused or failed; the previously active state is left untouched."""


class RecoveryInterrupted(MisError):
    """Test-only fault injection: recovery stopped before cutover."""


class DataError(MisError):
    """Imported data failed validation. ``problems`` lists row-level findings."""

    def __init__(self, message: str, problems: list[str] | None = None) -> None:
        super().__init__(message)
        self.problems = problems or []
