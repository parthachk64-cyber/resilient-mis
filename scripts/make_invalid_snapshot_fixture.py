"""Write the committed invalid-snapshot fixture: fixed bytes, a throwaway signing key, never a trusted key.

The manifest is signed by a key that is NOT any deployment's manifest key, and the payload is a fixed byte string, so
``verify`` must reject it at the signature stage in every home. Re-running regenerates different signature bytes; the committed
copy under src/resilient_mis/data/invalid_snapshot/ is what the walkthrough and tests use.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519

from resilient_mis.crypto import canonical_json, sha256_hex

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "src" / "resilient_mis" / "data" / "invalid_snapshot"
OUT.mkdir(parents=True, exist_ok=True)
blob = b"NOT-A-REAL-SNAPSHOT:" + bytes(range(64))
(OUT / "store.db.enc").write_bytes(blob)
manifest = {"manifest_version": 1, "snapshot_id": "snap-999999-deadbeef", "sequence": 999999, "schema_version": "store.v1",
            "created_at": "2026-01-01T00:00:00.000Z", "scope": {"dataset": "po-register", "tenants": ["tenant-a", "tenant-b"]},
            "last_txn_id": 1, "last_txn_hash": "0" * 64, "record_versions": 1, "business_digest": "0" * 64, "wrap_key_id": "wrap-backup-g001",
            "files": [{"name": "store.db.enc", "sha256": sha256_hex(blob), "bytes": len(blob)}], "signer_fingerprint": "throwaway"}
(OUT / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
key = ed25519.Ed25519PrivateKey.generate()
(OUT / "manifest.sig").write_text(base64.b64encode(key.sign(canonical_json(manifest))).decode("ascii"), encoding="ascii")
print("wrote", OUT)
