"""Local key custody. Private material lives only under ``<home>/keys`` (never in the database, backups, logs or Git).

* RSA wrapping keys: one per tenant plus one for backups, versioned by generation (``wrap-<scope>-gNNN``).
  Rotation creates a new generation for new writes; every earlier generation is RETAINED so old backups stay readable.
* Ed25519 signing keys: ``manifest`` (snapshot manifests, approved checkpoints) and ``journal`` (write-ahead journal),
  independent of each other and of the wrapping keys.
* A telemetry HMAC key pseudonymises principals.

Trust model limits: keys are PEM files with owner-only permissions (best effort on Windows). Anyone who can read the
``keys`` directory can decrypt everything. Setting ``MIS_KEY_PASSPHRASE`` encrypts PEMs at rest, but the passphrase
then lives in the process environment. Production use needs an HSM/KMS; this companion does not provide one.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from resilient_mis.errors import KeyCustodyError

PASSPHRASE_ENV = "MIS_KEY_PASSPHRASE"
_SCOPE = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}$")
SIGNING_PURPOSES = ("manifest", "journal")


def _encryption() -> serialization.KeySerializationEncryption:
    pw = os.environ.get(PASSPHRASE_ENV)
    return serialization.BestAvailableEncryption(pw.encode()) if pw else serialization.NoEncryption()


def _password() -> bytes | None:
    pw = os.environ.get(PASSPHRASE_ENV)
    return pw.encode() if pw else None


def _write_new(path: Path, data: bytes, mode: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def public_fingerprint(pub) -> str:
    der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def load_verify_key(path: Path) -> ed25519.Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(Path(path).read_bytes())
    except (OSError, ValueError) as exc:
        raise KeyCustodyError(f"cannot load verification key {path}") from exc
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise KeyCustodyError("verification key is not Ed25519")
    return key


def verify_signature(pub: ed25519.Ed25519PublicKey, signature: bytes, data: bytes) -> bool:
    try:
        pub.verify(signature, data)
        return True
    except InvalidSignature:
        return False


class KeyStore:
    def __init__(self, home: Path) -> None:
        self.home = Path(home)
        self.keys_dir = self.home / "keys"
        self.trust_dir = self.home / "trust"
        self._priv_cache: dict[str, rsa.RSAPrivateKey] = {}
        self._sign_cache: dict[str, ed25519.Ed25519PrivateKey] = {}
        self.cold_loads = 0

    # -- creation ---------------------------------------------------------------------------------------------
    @classmethod
    def create(cls, home: Path, tenants: list[str], rsa_bits: int = 3072) -> KeyStore:
        ks = cls(home)
        ks.keys_dir.mkdir(parents=True, exist_ok=True)
        ks.trust_dir.mkdir(parents=True, exist_ok=True)
        if (ks.keys_dir / "index.json").exists():
            raise KeyCustodyError("keys already exist in this home; refusing to overwrite")
        for scope in [*tenants, "backup"]:
            ks.rotate(scope, rsa_bits=rsa_bits)
        for purpose in SIGNING_PURPOSES:
            priv = ed25519.Ed25519PrivateKey.generate()
            _write_new(ks.keys_dir / f"sign-{purpose}.pem",
                       priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, _encryption()), 0o600)
            pub = priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            _write_new(ks.trust_dir / f"{purpose}-verify.pub", pub, 0o644)
        _write_new(ks.keys_dir / "telemetry.key", secrets.token_bytes(32), 0o600)
        anchor = {f"{p}_verify_fingerprint": public_fingerprint(load_verify_key(ks.trust_dir / f"{p}-verify.pub")) for p in SIGNING_PURPOSES}
        _write_new(ks.trust_dir / "anchor.json", json.dumps(anchor, indent=2, sort_keys=True).encode(), 0o644)
        return ks

    # -- wrapping keys ----------------------------------------------------------------------------------------
    def _index_read(self) -> dict[str, int]:
        try:
            return json.loads((self.keys_dir / "index.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise KeyCustodyError("key index missing or unreadable") from exc

    def _index_write(self, index: dict[str, int]) -> None:
        tmp = self.keys_dir / "index.json.tmp"
        tmp.write_text(json.dumps(index, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.keys_dir / "index.json")

    def rotate(self, scope: str, rsa_bits: int = 3072) -> str:
        """Create the next generation for ``scope``. Earlier generations are retained, never deleted."""
        if not _SCOPE.match(scope):
            raise KeyCustodyError("invalid key scope")
        index = self._index_read() if (self.keys_dir / "index.json").exists() else {}
        gen = index.get(scope, 0) + 1
        key_id = f"wrap-{scope}-g{gen:03d}"
        priv = rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
        _write_new(self.keys_dir / f"{key_id}.pem",
                   priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, _encryption()), 0o600)
        _write_new(self.trust_dir / f"{key_id}.pub.pem",
                   priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo), 0o644)
        index[scope] = gen
        self._index_write(index)
        return key_id

    def latest_key_id(self, scope: str) -> str:
        index = self._index_read()
        if scope not in index:
            raise KeyCustodyError(f"no wrapping key for scope {scope!r}")
        return f"wrap-{scope}-g{index[scope]:03d}"

    def public_wrap(self, key_id: str) -> rsa.RSAPublicKey:
        try:
            key = serialization.load_pem_public_key((self.trust_dir / f"{key_id}.pub.pem").read_bytes())
        except (OSError, ValueError) as exc:
            raise KeyCustodyError(f"public wrapping key {key_id} unavailable") from exc
        if not isinstance(key, rsa.RSAPublicKey):
            raise KeyCustodyError("wrapping key is not RSA")
        return key

    def private_wrap(self, key_id: str) -> rsa.RSAPrivateKey:
        if not re.match(r"^wrap-[a-z0-9-]+-g\d{3}$", key_id):
            raise KeyCustodyError("malformed key id")
        cached = self._priv_cache.get(key_id)
        if cached is not None:
            return cached
        try:
            key = serialization.load_pem_private_key((self.keys_dir / f"{key_id}.pem").read_bytes(), password=_password())
        except (OSError, ValueError, TypeError) as exc:
            raise KeyCustodyError(f"private wrapping key {key_id} unavailable") from exc
        if not isinstance(key, rsa.RSAPrivateKey):
            raise KeyCustodyError("wrapping key is not RSA")
        self.cold_loads += 1
        self._priv_cache[key_id] = key
        return key

    def drop_cache(self) -> None:
        """Forget loaded private keys (used to measure first-use key loading)."""
        self._priv_cache.clear()
        self._sign_cache.clear()

    # -- signing ----------------------------------------------------------------------------------------------
    def _signer(self, purpose: str) -> ed25519.Ed25519PrivateKey:
        if purpose not in SIGNING_PURPOSES:
            raise KeyCustodyError("unknown signing purpose")
        if purpose not in self._sign_cache:
            try:
                key = serialization.load_pem_private_key((self.keys_dir / f"sign-{purpose}.pem").read_bytes(), password=_password())
            except (OSError, ValueError, TypeError) as exc:
                raise KeyCustodyError(f"signing key {purpose} unavailable") from exc
            if not isinstance(key, ed25519.Ed25519PrivateKey):
                raise KeyCustodyError("signing key is not Ed25519")
            self._sign_cache[purpose] = key
        return self._sign_cache[purpose]

    def sign(self, purpose: str, data: bytes) -> bytes:
        return self._signer(purpose).sign(data)

    def verify_key(self, purpose: str) -> ed25519.Ed25519PublicKey:
        return load_verify_key(self.trust_dir / f"{purpose}-verify.pub")

    # -- telemetry pseudonyms ---------------------------------------------------------------------------------
    def pseudonym(self, principal: str) -> str:
        try:
            key = (self.keys_dir / "telemetry.key").read_bytes()
        except OSError as exc:
            raise KeyCustodyError("telemetry key unavailable") from exc
        return "p-" + hmac.new(key, principal.encode("utf-8"), hashlib.sha256).hexdigest()[:12]
