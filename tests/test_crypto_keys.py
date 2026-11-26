from __future__ import annotations

import os
import sys

import pytest

from resilient_mis import crypto
from resilient_mis.errors import IntegrityError, KeyCustodyError
from resilient_mis.keys import KeyStore
from resilient_mis.records import SCHEMA


@pytest.fixture()
def ks(fx):
    return fx.svc.keys


def _seal(ks, tenant="tenant-a", rid="PO-1", version=1, data=b"secret payload"):
    key_id = ks.latest_key_id(tenant)
    return crypto.seal(data, crypto.record_aad(tenant, rid, SCHEMA, version), ks.public_wrap(key_id), key_id)


def test_encrypted_round_trip(ks):
    env = _seal(ks)
    out = crypto.open_envelope(env, crypto.record_aad("tenant-a", "PO-1", SCHEMA, 1), ks.private_wrap)
    assert out == b"secret payload"
    assert b"secret payload" not in str(env).encode()


@pytest.mark.parametrize("tenant,rid,version", [("tenant-b", "PO-1", 1), ("tenant-a", "PO-2", 1), ("tenant-a", "PO-1", 2)])
def test_wrong_authenticated_context_fails(ks, tenant, rid, version):
    env = _seal(ks)
    with pytest.raises(IntegrityError):
        crypto.open_envelope(env, crypto.record_aad(tenant, rid, SCHEMA, version), ks.private_wrap)


def test_wrong_key_fails(ks):
    env = _seal(ks)
    env["key_id"] = ks.latest_key_id("tenant-b")
    with pytest.raises(IntegrityError):
        crypto.open_envelope(env, crypto.record_aad("tenant-a", "PO-1", SCHEMA, 1), ks.private_wrap)


@pytest.mark.parametrize("field", ["ct", "nonce", "wrapped_key"])
def test_tampering_fails_authenticity_check(ks, field):
    env = _seal(ks)
    raw = bytearray(crypto._unb64(env[field]))
    raw[0] ^= 1
    env[field] = crypto._b64(bytes(raw))
    with pytest.raises(IntegrityError):
        crypto.open_envelope(env, crypto.record_aad("tenant-a", "PO-1", SCHEMA, 1), ks.private_wrap)


@pytest.mark.parametrize("bad", [{}, {"v": 1}, {"v": 2, "alg": "x"}, {"v": 1, "alg": crypto.ALGORITHM, "key_id": "wrap-tenant-a-g001", "nonce": "!!", "wrapped_key": "", "ct": ""}])
def test_malformed_envelopes_are_integrity_errors(ks, bad):
    with pytest.raises(IntegrityError):
        crypto.open_envelope(bad, b"aad", ks.private_wrap)


def test_aad_encoding_is_unambiguous():
    assert crypto.encode_aad("ab", "c") != crypto.encode_aad("a", "bc")
    assert crypto.encode_aad("a") != crypto.encode_aad("a", "")


def test_fresh_data_key_and_nonce_per_seal(ks):
    a, b = _seal(ks), _seal(ks)
    assert a["nonce"] != b["nonce"] and a["wrapped_key"] != b["wrapped_key"] and a["ct"] != b["ct"]


def test_key_rotation_across_retained_backup(fx):
    from resilient_mis.recovery import recover
    from resilient_mis.scenario import inject_fault
    from resilient_mis.snapshots import create_checkpoint

    create_checkpoint(fx.home, fx.svc.keys, fx.svc.store, __import__("time").time)  # sealed under backup g001
    old_tenant, old_backup = fx.svc.keys.latest_key_id("tenant-a"), fx.svc.keys.latest_key_id("backup")
    fx.svc.keys.rotate("tenant-a", rsa_bits=2048)
    fx.svc.keys.rotate("backup", rsa_bits=2048)
    assert fx.svc.keys.latest_key_id("tenant-a") != old_tenant
    fx.client.create(fx.tokens["manager_a"], "tenant-a", "PO-NEW", "ops", "Acme", "USD", 100, "approved")
    assert fx.svc.read_order(fx.tokens["manager_a"], "tenant-a", "PO-000001").record_id == "PO-000001"  # old-generation record still opens
    inject_fault(fx.home, "delete")
    fresh_keys = KeyStore(fx.home.root)  # a new process would reload keys from disk
    assert fresh_keys.private_wrap(old_backup) is not None
    rep = recover(fx.svc, fx.tokens["recovery"])
    assert rep.outcome == "restored" and rep.journal_entries_replayed >= 1  # journal replay includes a g002 record


def test_missing_private_key_is_a_custody_error(fx):
    (fx.home.keys / f"{fx.svc.keys.latest_key_id('tenant-a')}.pem").unlink()
    fx.svc.keys.drop_cache()
    with pytest.raises(KeyCustodyError):
        fx.svc.keys.private_wrap(fx.svc.keys.latest_key_id("tenant-a"))


def test_create_refuses_to_overwrite_existing_keys(fx):
    with pytest.raises(KeyCustodyError):
        KeyStore.create(fx.home.root, ["tenant-a"], rsa_bits=2048)


def test_pseudonyms_are_stable_and_distinct(ks):
    assert ks.pseudonym("alice") == ks.pseudonym("alice") != ks.pseudonym("bob")
    assert "alice" not in ks.pseudonym("alice")


def test_cold_key_load_is_counted(fx):
    fx.svc.keys.drop_cache()
    n = fx.svc.keys.cold_loads
    fx.svc.read_order(fx.tokens["manager_a"], "tenant-a", "PO-000001")
    assert fx.svc.keys.cold_loads == n + 1


def test_passphrase_protected_private_keys(tmp_path, monkeypatch):
    from resilient_mis.keys import PASSPHRASE_ENV

    monkeypatch.setenv(PASSPHRASE_ENV, "correct horse")
    k = KeyStore.create(tmp_path / "h", ["tenant-a"], rsa_bits=2048)
    assert b"ENCRYPTED" in (k.keys_dir / "wrap-tenant-a-g001.pem").read_bytes()
    assert k.private_wrap("wrap-tenant-a-g001") is not None
    monkeypatch.setenv(PASSPHRASE_ENV, "wrong")
    with pytest.raises(KeyCustodyError):
        KeyStore(tmp_path / "h").private_wrap("wrap-tenant-a-g001")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_private_keys_are_owner_only(ks):
    assert os.stat(ks.keys_dir / "wrap-tenant-a-g001.pem").st_mode & 0o077 == 0


def test_no_private_material_outside_keys_dir(fx):
    for p in fx.home.root.rglob("*"):
        if p.is_file() and "keys" not in p.relative_to(fx.home.root).parts[:1]:
            assert b"PRIVATE KEY" not in p.read_bytes()[:4096] or p.suffix in (".sqlite",), p
