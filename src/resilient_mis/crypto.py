"""Envelope encryption built only from reviewed ``cryptography`` APIs.

Per record version: a fresh 256-bit AES-GCM data key and a fresh 96-bit nonce (both from the OS CSPRNG) encrypt the
payload; the data key is wrapped with RSA-OAEP (MGF1-SHA256, SHA-256). The associated data binds tenant, record id,
schema and version with an unambiguous length-prefixed encoding, and the OAEP label is the SHA-256 of that same
associated data, so a wrapped key cannot be replayed under another identity either.

No seed ever reaches this module: keys and nonces come from ``os.urandom`` through the library only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
from collections.abc import Callable
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from resilient_mis.errors import IntegrityError

ALGORITHM = "AES-256-GCM+RSA-OAEP-SHA256"
_MAGIC = b"RMIS-AAD1"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON bytes (sorted keys, no whitespace, ASCII only)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def encode_aad(*fields: str) -> bytes:
    """Unambiguous encoding: magic, field count, then each field as a 4-byte length plus UTF-8 bytes."""
    out = bytearray(_MAGIC)
    out += struct.pack(">I", len(fields))
    for f in fields:
        raw = f.encode("utf-8")
        out += struct.pack(">I", len(raw)) + raw
    return bytes(out)


def record_aad(tenant: str, record_id: str, schema: str, version: int) -> bytes:
    return encode_aad("record", tenant, record_id, schema, str(int(version)))


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    try:
        return base64.b64decode(s.encode("ascii"), validate=True)
    except Exception as exc:  # malformed base64 is an integrity failure, not a crash
        raise IntegrityError("malformed envelope encoding") from exc


def _oaep(label: bytes) -> padding.OAEP:
    return padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=label)


def seal(plaintext: bytes, aad: bytes, wrap_public: RSAPublicKey, key_id: str) -> dict[str, Any]:
    """Encrypt ``plaintext`` for ``aad``; returns a JSON-serialisable envelope."""
    data_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(data_key).encrypt(nonce, plaintext, aad)
    wrapped = wrap_public.encrypt(data_key, _oaep(hashlib.sha256(aad).digest()))
    return {"v": 1, "alg": ALGORITHM, "key_id": key_id, "nonce": _b64(nonce), "wrapped_key": _b64(wrapped), "ct": _b64(ciphertext)}


def open_envelope(env: dict[str, Any], aad: bytes, private_lookup: Callable[[str], RSAPrivateKey]) -> bytes:
    """Authenticate and decrypt. Any failure (wrong key, wrong context, tampering) raises ``IntegrityError``."""
    if not isinstance(env, dict) or env.get("v") != 1 or env.get("alg") != ALGORITHM:
        raise IntegrityError("unsupported or malformed envelope")
    try:
        key_id = str(env["key_id"])
        nonce, wrapped, ct = _unb64(env["nonce"]), _unb64(env["wrapped_key"]), _unb64(env["ct"])
    except KeyError as exc:
        raise IntegrityError("envelope is missing a field") from exc
    if len(nonce) != 12:
        raise IntegrityError("bad nonce length")
    try:
        priv = private_lookup(key_id)
        data_key = priv.decrypt(wrapped, _oaep(hashlib.sha256(aad).digest()))
        return AESGCM(data_key).decrypt(nonce, ct, aad)
    except InvalidTag as exc:
        raise IntegrityError("authentication tag mismatch") from exc
    except ValueError as exc:  # OAEP decryption failure (wrong key, wrong label, tampered wrap)
        raise IntegrityError("key unwrap failed") from exc


def seal_plain(plaintext: bytes) -> dict[str, Any]:
    """TEST-ONLY reduced-protection envelope used by the benchmark harness; never produced by the service."""
    return {"v": 0, "alg": "none", "plain": _b64(plaintext)}


def open_plain(env: dict[str, Any]) -> bytes:
    return _unb64(env["plain"])
