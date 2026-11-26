from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from resilient_mis.config import load_config
from resilient_mis.scenario import Fixture, build_fixture


@pytest.fixture(scope="session")
def cfg():
    c = load_config()
    c["rsa_bits"] = 2048  # speed only; production default is 3072
    return c


@pytest.fixture(scope="session")
def key_template(tmp_path_factory, cfg):
    root = tmp_path_factory.mktemp("keys") / "tpl"
    build_fixture(root, cfg, 1, with_data=False)
    return root


@pytest.fixture()
def fx(tmp_path, cfg, key_template) -> Fixture:
    f = build_fixture(tmp_path / "home", cfg, 8, keys_from=key_template)
    yield f
    shutil.rmtree(tmp_path, ignore_errors=True)


@pytest.fixture()
def make_fx(tmp_path, cfg, key_template):
    n = {"i": 0}

    def _make(**kw) -> Fixture:
        n["i"] += 1
        return build_fixture(tmp_path / f"h{n['i']}", cfg, kw.pop("n_orders", 6), keys_from=key_template, **kw)

    return _make


def corrupt_file(path: Path) -> None:
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0xFF
    path.write_bytes(bytes(data))
