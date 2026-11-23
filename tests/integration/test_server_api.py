"""Servidor real (HTTP + SQLite) frente al evaluador del protocolo: carga, auditorías y errores."""

import random

import pytest
from support import BLOCK, ServerHarness

from merkle_audit.core.encoding import to_hex
from merkle_audit.protocol.verify import Cause, Status

FID = bytes(range(16))


def _data(size: int, seed: int = 0) -> bytes:
    return random.Random(seed).randbytes(size)  # noqa: S311 (datos de prueba repetibles)


@pytest.fixture
def server(tmp_path):
    return ServerHarness(tmp_path)


@pytest.fixture
def manifest(server):
    return server.upload(_data(19 * BLOCK + 1234))  # 20 bloques, el último corto


def _error(r, status: int, code: str, audit_id="any"):
    assert r.status_code == status, r.text
    body = r.json()
    assert body["type"] == "error" and body["code"] == code
    if audit_id != "any":
        assert body["audit_id"] == audit_id


# --- Carga --------------------------------------------------------------------------------------


@pytest.mark.parametrize("size", [1, BLOCK - 1, BLOCK, 5 * BLOCK + 7])
def test_honest_upload_and_full_audit_pass(server, size):
    manifest = server.upload(_data(size))  # comprueba el recibo contra el árbol del cliente
    r, result = server.audit(manifest)
    assert r.status_code == 200
    assert result.status is Status.PASS, result.findings
    assert not result.trivial


def test_empty_file_passes_trivially(server):
    manifest = server.upload(b"")
    r, result = server.audit(manifest, q=0)
    assert r.status_code == 200 and r.json()["proofs"] == []
    assert result.status is Status.PASS and result.trivial


@pytest.mark.parametrize("block_size", [8192, 65536])
def test_other_block_sizes(server, block_size):
    manifest = server.upload(_data(3 * block_size + 1), block_size=block_size)
    assert server.audit(manifest)[1].status is Status.PASS


def test_sampled_audits_pass(server, manifest):
    for q in (1, 5, 20):
        assert server.audit(manifest, q=q)[1].status is Status.PASS


def test_each_version_is_audited_on_its_own(server):
    v1 = server.upload(b"primera version" * 1000)
    v2 = server.upload(b"segunda" * 3000, version=2)
    assert server.audit(v1)[1].status is Status.PASS
    assert server.audit(v2)[1].status is Status.PASS


def test_version_exists(server, manifest):
    _error(server.put(FID, 1, b"otro contenido"), 409, "VERSION_EXISTS")


@pytest.mark.parametrize("version", [2, 0])
def test_first_version_must_be_one(server, version):
    _error(server.put(FID, version, b"x"), 400, "BAD_REQUEST")


def test_versions_must_be_consecutive(server, manifest):
    _error(server.put(FID, 3, b"x"), 400, "BAD_REQUEST")
    assert server.put(FID, 2, b"x").status_code == 201


@pytest.mark.parametrize(
    "params",
    [
        {"block_size": 1000},
        {"block_size": "abc"},
        {"block_size": -4096},
        {"file_size": 3},  # el cuerpo mide 10
        {"file_size": 11},
        {"file_size": 500 * 1024 * 1024 + 1},
    ],
)
def test_bad_upload_parameters(server, params):
    _error(server.put(FID, 1, b"0123456789", **params), 400, "BAD_REQUEST")
    assert server.store.versions(FID) == []


@pytest.mark.parametrize(
    "path",
    [
        "/files/" + "AB" * 16 + "/versions/1",  # hex en mayúsculas
        "/files/" + "ab" * 15 + "/versions/1",  # longitud distinta
        "/files/" + "ab" * 16 + "/versions/uno",
        "/files/" + "ab" * 16 + "/versions/-1",
    ],
)
def test_bad_upload_path(server, path):
    r = server.http.put(path, params={"block_size": BLOCK, "file_size": 1}, content=b"x")
    _error(r, 400, "BAD_REQUEST")


def test_missing_query_parameters(server):
    r = server.http.put(f"/files/{to_hex(FID)}/versions/1", content=b"x")
    _error(r, 400, "BAD_REQUEST")


# --- Errores de la auditoría --------------------------------------------------------------------


@pytest.mark.parametrize("body", [b"", b"no es json", b"[]", b'{"type": "challenge"}'])
def test_unparseable_challenge(server, manifest, body):
    _error(server.send(body), 400, "BAD_REQUEST", audit_id=None)


def test_challenge_with_extra_field(server, manifest):
    msg = {
        "protocol": "merkle-audit/1",
        "type": "challenge",
        "audit_id": "00" * 16,
        "file_id": to_hex(FID),
        "version": 1,
        "commitment": to_hex(manifest.commitment),
        "indices": [0],
        "extra": 1,
    }
    _error(server.send(msg), 400, "BAD_REQUEST", audit_id=None)


def test_unknown_file(server, manifest):
    other = server.upload(b"otro archivo", file_id=bytes(16))
    # se borra el archivo de la base para simular un servidor que no lo conoce
    with server.store.connect() as conn:
        conn.execute("DELETE FROM versions WHERE file_id = ?", (bytes(16),))
    r, result = server.audit(other)
    _error(r, 404, "UNKNOWN_FILE")
    assert result.status is Status.CORRUPT
    assert result.findings[0].cause is Cause.FILE_MISSING


def test_unknown_version(server, manifest):
    v2 = server.upload(b"version dos", version=2)
    with server.store.connect() as conn:
        conn.execute("DELETE FROM versions WHERE version = 2")
    r, result = server.audit(v2)
    _error(r, 404, "UNKNOWN_VERSION")
    assert result.status is Status.CORRUPT
    assert result.findings[0].cause is Cause.FILE_MISSING
    assert result.server_error_code == "UNKNOWN_VERSION"


def test_commitment_mismatch(server, manifest):
    # el cliente audita con otro manifiesto para el mismo (file_id, versión)
    other = ServerHarness(server.store.home / "otro").upload(_data(3 * BLOCK, seed=9))
    r, result = server.audit(other)
    _error(r, 409, "COMMITMENT_MISMATCH")
    assert result.status is Status.INVALID
    assert result.findings[0].cause is Cause.SERVER_ERROR


@pytest.mark.parametrize(
    "indices",
    [
        [3, 1],  # desordenados
        [2, 2],  # repetidos
        [0, 20],  # fuera de rango
        [],  # q = 0 con n > 0
    ],
)
def test_bad_indices(server, manifest, indices):
    r, result = server.audit(manifest, indices=indices)
    _error(r, 400, "BAD_REQUEST", audit_id="00" * 16)
    assert result.status is Status.INVALID


def test_q_above_q_max(tmp_path):
    server = ServerHarness(tmp_path, q_max=4)
    manifest = server.upload(_data(10 * BLOCK))
    r, _ = server.audit(manifest, indices=[0, 1, 2, 3, 4])
    _error(r, 400, "BAD_REQUEST")
    assert server.audit(manifest, indices=[0, 1, 2, 3])[1].status is Status.PASS


@pytest.mark.parametrize(
    "method, path", [("GET", "/audit"), ("GET", "/no-existe"), ("DELETE", "/files/x")]
)
def test_unknown_route(server, method, path):
    _error(server.http.request(method, path), 400, "BAD_REQUEST", audit_id=None)


def test_store_failure_is_internal(server, manifest, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("disco lleno")

    monkeypatch.setattr(server.store, "tree", boom)
    r, result = server.audit(manifest, q=2)
    _error(r, 500, "INTERNAL")
    assert result.status is Status.INVALID


def test_missing_live_block_is_declared(server, manifest):
    with server.store.connect() as conn:
        conn.execute("DELETE FROM blocks WHERE idx = 4")
    r, result = server.audit(manifest, indices=[3, 4, 5])
    proofs = r.json()["proofs"]
    assert proofs[1] == {"index": 4, "block": None, "path": []}
    assert result.status is Status.CORRUPT
    assert [(f.index, f.cause) for f in result.findings] == [(4, Cause.BLOCK_MISSING)]
