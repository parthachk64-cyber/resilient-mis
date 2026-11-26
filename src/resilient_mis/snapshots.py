"""Encrypted snapshots, signed manifests and the approved-checkpoint chain.

A snapshot is an SQLite online-backup copy of the store (transactionally consistent), encrypted as one AES-GCM envelope
under the backup wrapping key, with a manifest signed by the independent ``manifest`` signing key. The manifest names
file digests, tenant scope, schema version, snapshot id, sequence, the last committed business transaction and a digest
of the business state (never the values).

The latest APPROVED checkpoint is tracked in ``trust/checkpoints.jsonl`` (outside the recoverable data, hash-chained and
signed) so a stale-but-valid snapshot, a snapshot nobody approved, or a forged snapshot reusing an approved id is refused.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from resilient_mis.crypto import canonical_json, encode_aad, open_envelope, seal, sha256_hex
from resilient_mis.errors import IntegrityError, KeyCustodyError, SnapshotError
from resilient_mis.keys import KeyStore, load_verify_key, public_fingerprint, verify_signature
from resilient_mis.layout import Home
from resilient_mis.store import SCHEMA_VERSION, Store
from resilient_mis.telemetry import iso
from resilient_mis.verify import verify_store

CHECKPOINT_GENESIS = "0" * 64
BLOB_NAME = "store.db.enc"


def snapshot_aad(snapshot_id: str, sequence: int, schema_version: str) -> bytes:
    return encode_aad("snapshot", snapshot_id, str(int(sequence)), schema_version)


def manifest_sha256(manifest: dict[str, Any]) -> str:
    return sha256_hex(canonical_json(manifest))


class TrustState:
    """Approved-checkpoint chain and the monotonic snapshot sequence counter (both outside the recoverable data)."""

    def __init__(self, trust_dir: Path) -> None:
        self.dir = Path(trust_dir)
        self.chain = self.dir / "checkpoints.jsonl"
        self.counter = self.dir / "sequence"

    def next_sequence(self) -> int:
        cur = int(self.counter.read_text(encoding="utf-8")) if self.counter.exists() else 0
        tmp = self.counter.with_suffix(".tmp")
        tmp.write_text(str(cur + 1), encoding="utf-8")
        os.replace(tmp, self.counter)
        return cur + 1

    def entries(self, pub) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if not self.chain.exists():
            return out
        prev = CHECKPOINT_GENESIS
        with self.chain.open("rb") as fh:
            for n, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                try:
                    d = json.loads(line)
                    body = d["body"]
                    sig = base64.b64decode(d["sig"], validate=True)
                except (ValueError, KeyError, TypeError) as exc:
                    raise SnapshotError("checkpoint_chain_invalid", f"line {n} is malformed") from exc
                h = sha256_hex(canonical_json([prev, body]))
                if d["prev"] != prev or d["hash"] != h or not verify_signature(pub, sig, h.encode("ascii")):
                    raise SnapshotError("checkpoint_chain_invalid", f"approved-checkpoint record {n} failed verification")
                out.append(body)
                prev = h
        return out

    def append(self, keys: KeyStore, body: dict[str, Any]) -> None:
        entries = self.entries(keys.verify_key("manifest"))
        prev = CHECKPOINT_GENESIS
        if entries:
            prev = _last_hash(self.chain)
        h = sha256_hex(canonical_json([prev, body]))
        sig = base64.b64encode(keys.sign("manifest", h.encode("ascii"))).decode("ascii")
        with self.chain.open("ab") as fh:
            fh.write(json.dumps({"body": body, "prev": prev, "hash": h, "sig": sig}, sort_keys=True).encode("utf-8") + b"\n")
            fh.flush()
            os.fsync(fh.fileno())

    def latest(self, pub) -> dict[str, Any] | None:
        e = self.entries(pub)
        return e[-1] if e else None


def _last_hash(path: Path) -> str:
    last = b""
    with path.open("rb") as fh:
        for line in fh:
            if line.strip():
                last = line
    return json.loads(last)["hash"]


@dataclass(frozen=True)
class VerifiedSnapshot:
    path: Path
    manifest: dict[str, Any]
    manifest_sha256: str

    @property
    def snapshot_id(self) -> str:
        return self.manifest["snapshot_id"]


def create_snapshot(home: Home, keys: KeyStore, store: Store, clock) -> Path:
    """Write ``backups/<snapshot_id>/``. The snapshot is NOT trusted until ``approve_checkpoint`` records it."""
    trust = TrustState(home.trust)
    seq = trust.next_sequence()
    sid = f"snap-{seq:06d}-{secrets.token_hex(4)}"
    home.staging.mkdir(parents=True, exist_ok=True)
    tmp = home.staging / f"{sid}.db"
    store.backup_to(tmp)
    try:
        copy = Store(tmp, fence_path=tmp.with_name(tmp.name + ".FENCED"))
        v = verify_store(copy, keys)
        if not v.ok:
            raise SnapshotError("source_unhealthy", "; ".join(v.problems))
        raw = tmp.read_bytes()
        tenants = json.loads(copy.meta("tenants") or "[]")
        key_id = keys.latest_key_id("backup")
        env = seal(raw, snapshot_aad(sid, seq, SCHEMA_VERSION), keys.public_wrap(key_id), key_id)
        blob = canonical_json(env)
    finally:
        tmp.unlink(missing_ok=True)
    out = home.backups / sid
    out.mkdir(parents=True)
    (out / BLOB_NAME).write_bytes(blob)
    manifest = {"manifest_version": 1, "snapshot_id": sid, "sequence": seq, "schema_version": SCHEMA_VERSION,
                "created_at": iso(clock()), "scope": {"dataset": "po-register", "tenants": sorted(tenants)},
                "last_txn_id": v.last_txn_id, "last_txn_hash": v.last_txn_hash, "record_versions": v.record_versions,
                "business_digest": v.business_digest, "wrap_key_id": key_id,
                "files": [{"name": BLOB_NAME, "sha256": sha256_hex(blob), "bytes": len(blob)}],
                "signer_fingerprint": public_fingerprint(keys.verify_key("manifest"))}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    (out / "manifest.sig").write_text(base64.b64encode(keys.sign("manifest", canonical_json(manifest))).decode("ascii"), encoding="ascii")
    return out


def verify_snapshot(snap_dir: Path, trust_dir: Path, *, require_approved: bool = True, expected_tenants: list[str] | None = None,
                    allow_stale: bool = False, anchor_path: Path | None = None) -> VerifiedSnapshot:
    """Validate a candidate with the independently trusted verification key. Raises ``SnapshotError`` with a stable reason."""
    snap_dir, trust_dir = Path(snap_dir), Path(trust_dir)
    try:
        manifest = json.loads((snap_dir / "manifest.json").read_text(encoding="utf-8"))
        sig = base64.b64decode((snap_dir / "manifest.sig").read_text(encoding="ascii").strip(), validate=True)
    except (OSError, ValueError) as exc:
        raise SnapshotError("missing_manifest", "manifest or signature missing or malformed") from exc
    pub = load_verify_key(trust_dir / "manifest-verify.pub")
    try:
        anchor = json.loads((anchor_path or trust_dir / "anchor.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SnapshotError("anchor_missing", "trust anchor unavailable") from exc
    if anchor.get("manifest_verify_fingerprint") != public_fingerprint(pub):
        raise SnapshotError("anchor_mismatch", "verification key does not match the pinned trust anchor")
    if not isinstance(manifest, dict) or not verify_signature(pub, sig, canonical_json(manifest)):
        raise SnapshotError("bad_signature", "manifest signature does not verify under the trusted key")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise SnapshotError("schema_unsupported", f"schema {manifest.get('schema_version')!r} is not {SCHEMA_VERSION!r}")
    for f in manifest.get("files", []):
        p = snap_dir / f["name"]
        if not p.is_file():
            raise SnapshotError("missing_file", f["name"])
        data = p.read_bytes()
        if len(data) != f["bytes"] or sha256_hex(data) != f["sha256"]:
            raise SnapshotError("digest_mismatch", f"{f['name']} does not match the signed manifest")
    if expected_tenants is not None and sorted(manifest["scope"]["tenants"]) != sorted(expected_tenants):
        raise SnapshotError("scope_mismatch", "snapshot tenant scope differs from this deployment")
    msha = manifest_sha256(manifest)
    latest = TrustState(trust_dir).latest(pub)
    if latest is not None and manifest["sequence"] < latest["sequence"] and not allow_stale:
        raise SnapshotError("stale_snapshot", f"sequence {manifest['sequence']} is older than approved checkpoint {latest['sequence']}")
    if require_approved:
        approved = [e for e in TrustState(trust_dir).entries(pub) if e["snapshot_id"] == manifest["snapshot_id"]]
        if not approved:
            raise SnapshotError("not_approved", "snapshot has no approved-checkpoint record")
        if approved[-1]["manifest_sha256"] != msha:
            raise SnapshotError("approval_mismatch", "manifest differs from the one that was approved")
    return VerifiedSnapshot(snap_dir, manifest, msha)


def approve_checkpoint(home: Home, keys: KeyStore, snap_dir: Path, clock) -> dict[str, Any]:
    v = verify_snapshot(snap_dir, home.trust, require_approved=False)
    body = {"snapshot_id": v.snapshot_id, "sequence": v.manifest["sequence"], "manifest_sha256": v.manifest_sha256,
            "last_txn_id": v.manifest["last_txn_id"], "approved_at": iso(clock())}
    TrustState(home.trust).append(keys, body)
    return body


def create_checkpoint(home: Home, keys: KeyStore, store: Store, clock) -> dict[str, Any]:
    """Snapshot, verify with the trust key, then record it as the latest approved checkpoint."""
    path = create_snapshot(home, keys, store, clock)
    body = approve_checkpoint(home, keys, path, clock)
    return {**body, "path": str(path)}


def decrypt_snapshot(v: VerifiedSnapshot, keys: KeyStore, dest: Path) -> Path:
    m = v.manifest
    try:
        env = json.loads((v.path / BLOB_NAME).read_bytes())
        raw = open_envelope(env, snapshot_aad(m["snapshot_id"], m["sequence"], m["schema_version"]), keys.private_wrap)
    except (ValueError, IntegrityError) as exc:
        raise SnapshotError("decrypt_failed", "snapshot could not be authenticated and decrypted") from exc
    except KeyCustodyError as exc:
        raise SnapshotError("key_unavailable", "the wrapping key for this snapshot is not available") from exc
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(raw)
    return dest
