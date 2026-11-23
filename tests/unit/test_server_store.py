import io
import random
import sqlite3
import tempfile

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from merkle_audit.core.merkle import EMPTY_ROOT, commit, tree_for_file, verify_block
from merkle_audit.server.store import (
    DB_NAME,
    HOME_ENV,
    SizeMismatch,
    Store,
    VersionExists,
    VersionOutOfOrder,
    default_home,
)

B = 4096
FID = bytes(range(16))
OTHER = bytes(16)


def _data(size: int, seed: int = 0) -> bytes:
    return random.Random(seed).randbytes(size)  # noqa: S311 (datos de prueba repetibles)


def _put(store: Store, data: bytes, version: int = 1, file_id: bytes = FID, block_size: int = B):
    return store.put_version(file_id, version, block_size, len(data), io.BytesIO(data))


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path)


def _check_all_proofs(store: Store, data: bytes, block_size: int = B) -> None:
    info = store.version_info(FID, 1)
    tree = store.tree(FID, 1)
    assert tree.n == info.n_blocks
    for i in range(info.n_blocks):
        x = store.block(FID, 1, i)
        assert x == data[i * block_size : (i + 1) * block_size]
        failure = verify_block(
            i,
            x,
            tree.path(i),
            n=info.n_blocks,
            block_size=block_size,
            file_size=info.file_size,
            root=info.root,
        )
        assert failure is None, (i, failure)


def test_receipt_matches_client_computation(store):
    data = _data(5 * B + 123)
    info = _put(store, data)
    tree, size = tree_for_file(io.BytesIO(data), B)
    assert (info.n_blocks, info.file_size, info.root) == (6, size, tree.root)
    assert info.commitment == commit(FID, 1, B, size, 6, tree.root)
    assert not info.dropped


@pytest.mark.parametrize("size", [1, B - 1, B, B + 1, 3 * B, 7 * B + 5])
def test_every_stored_path_verifies(store, size):
    data = _data(size)
    _put(store, data)
    _check_all_proofs(store, data)


@settings(max_examples=25, deadline=None)
@given(st.integers(min_value=1, max_value=40 * 1024), st.sampled_from([4096, 8192]))
def test_every_stored_path_verifies_property(size, block_size):
    with tempfile.TemporaryDirectory() as home:
        store = Store(home)
        data = _data(size, seed=size)
        _put(store, data, block_size=block_size)
        _check_all_proofs(store, data, block_size)


def test_empty_file(store):
    info = _put(store, b"")
    assert info.n_blocks == 0
    assert info.root == EMPTY_ROOT
    assert store.tree(FID, 1).n == 0
    assert store.block(FID, 1, 0) is None


def test_pristine_copy_matches_blocks(store):
    _put(store, _data(3 * B + 10))
    with sqlite3.connect(store.db_path) as conn:
        live = conn.execute("SELECT idx, data FROM blocks ORDER BY idx").fetchall()
        pristine = conn.execute("SELECT idx, data FROM pristine ORDER BY idx").fetchall()
    assert live == pristine and len(live) == 4


def test_paths_come_from_upload_not_from_live_blocks(store):
    _put(store, _data(4 * B))
    before = store.tree(FID, 1).path(2)
    with store.connect() as conn:
        conn.execute("UPDATE blocks SET data = ? WHERE idx = 2", (b"\x00" * B,))
    assert store.block(FID, 1, 2) == b"\x00" * B
    assert store.tree(FID, 1).path(2) == before


def test_versions_are_consecutive(store):
    _put(store, b"uno")
    _put(store, b"dos", version=2)
    assert store.versions(FID) == [1, 2]
    assert store.latest_version(FID) == 2
    with pytest.raises(VersionOutOfOrder):
        _put(store, b"cuatro", version=4)
    with pytest.raises(VersionOutOfOrder):
        _put(store, b"nuevo", version=2, file_id=OTHER)
    assert store.latest_version(OTHER) is None


def test_versions_are_immutable(store):
    _put(store, b"original")
    with pytest.raises(VersionExists):
        _put(store, b"otro contenido")
    assert store.block(FID, 1, 0) == b"original"


@pytest.mark.parametrize("declared, actual", [(10, 9), (10, 11), (0, 1), (B + 1, B)])
def test_body_size_must_match(store, declared, actual):
    with pytest.raises(SizeMismatch):
        store.put_version(FID, 1, B, declared, io.BytesIO(_data(actual)))
    # la transacción se deshace: no queda rastro de la versión
    assert store.versions(FID) == []
    with sqlite3.connect(store.db_path) as conn:
        for table in ("blocks", "pristine", "levels"):
            assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0  # noqa: S608


@pytest.mark.parametrize(
    "file_id, block_size, file_size",
    [(FID, 1000, 10), (FID, B, -1), (FID, B, 500 * 1024 * 1024 + 1), (b"corto", B, 10)],
)
def test_bad_parameters(store, file_id, block_size, file_size):
    with pytest.raises(ValueError):
        store.put_version(file_id, 1, block_size, file_size, io.BytesIO(b""))


def test_bulk_block_lookup(store):
    data = _data(1200 * B)  # más índices que el tamaño de tanda de la consulta
    _put(store, data)
    wanted = list(range(0, 1200, 1)) + [5000]
    found = store.blocks(FID, 1, wanted)
    assert sorted(found) == list(range(1200))
    assert found[777] == data[777 * B : 778 * B]


def test_data_persists_across_instances(tmp_path):
    _put(Store(tmp_path), b"persistente")
    again = Store(tmp_path)
    assert again.block(FID, 1, 0) == b"persistente"
    assert (tmp_path / DB_NAME).exists()


def test_default_home_from_environment(monkeypatch, tmp_path):
    monkeypatch.setenv(HOME_ENV, str(tmp_path / "srv"))
    assert default_home() == tmp_path / "srv"
    monkeypatch.delenv(HOME_ENV)
    assert default_home().name == ".merkle-audit-server"


def test_path_index_out_of_range(store):
    _put(store, _data(2 * B))
    with pytest.raises(ValueError):
        store.tree(FID, 1).path(2)
