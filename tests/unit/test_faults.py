"""Inyector de fallos: registro, reproducibilidad, validaciones y CLI."""

import json
import math

import pytest
from support import DATA_20, ServerHarness

from merkle_audit.core.encoding import to_hex
from merkle_audit.protocol.verify import Status
from merkle_audit.server.fault_cli import main
from merkle_audit.server.faults import (
    DamageOp,
    FaultError,
    Injector,
    ModifyMode,
    active_response_faults,
)

FID = bytes(range(16))


@pytest.fixture
def server(tmp_path):
    return ServerHarness(tmp_path / "srv")


@pytest.fixture
def manifest(server):
    return server.upload(DATA_20)


@pytest.fixture
def injector(server):
    return Injector(server.store)


def _faults(server) -> list[tuple]:
    with server.store.connect() as conn:
        return conn.execute(
            "SELECT op, version, params, seed, indices, active FROM faults ORDER BY id"
        ).fetchall()


def test_every_operation_is_logged(server, manifest, injector):
    injector.delete(FID, [3, 1])
    injector.modify(FID, [5], seed=7)
    injector.reset(FID)
    rows = _faults(server)
    assert [r[0] for r in rows] == ["delete", "modify", "reset"]
    op, version, params, seed, indices, active = rows[1]
    assert (version, json.loads(params), seed, json.loads(indices), active) == (
        1,
        {"mode": "bitflip"},
        7,
        [5],
        0,
    )
    assert json.loads(rows[0][4]) == [1, 3]  # índices ordenados y sin repetir


def test_seed_is_generated_when_missing(server, manifest, injector):
    applied = injector.modify(FID, [2])
    assert applied.seed is not None
    assert _faults(server)[0][3] == applied.seed


@pytest.mark.parametrize("eps", [0.01, 0.1, 0.5, 1.0])
def test_damage_touches_ceil_eps_n_blocks(server, manifest, injector, eps):
    applied = injector.damage(FID, eps, DamageOp.DELETE, seed=3)
    assert len(applied.indices) == math.ceil(eps * 20)
    missing = [i for i in range(20) if server.store.block(FID, 1, i) is None]
    assert missing == applied.indices


def test_damage_is_reproducible(server, manifest, injector):
    a = injector.damage(FID, 0.25, DamageOp.MODIFY, seed=11)
    injector.reset(FID)
    b = injector.damage(FID, 0.25, DamageOp.MODIFY, seed=11)
    assert a.indices == b.indices


def test_full_audit_detects_any_damage(server, manifest, injector):
    injector.damage(FID, 0.05, DamageOp.MODIFY, ModifyMode.TRUNCATE, seed=1)
    assert server.audit(manifest)[1].status is Status.CORRUPT


def test_operations_default_to_latest_version(server, manifest, injector):
    server.upload(DATA_20[::-1], version=2)
    assert injector.delete(FID, [0]).version == 2
    assert server.store.block(FID, 1, 0) is not None
    assert injector.delete(FID, [0], version=1).version == 1


def test_newer_rollback_replaces_older(server, manifest, injector):
    server.upload(b"v2", version=2)
    server.upload(b"v3", version=3)
    injector.rollback(FID, to=1, declare=True)
    injector.rollback(FID, to=2, declare=False)
    faults = active_response_faults(server.store, FID, 3)
    assert (faults.rollback_to, faults.declare) == (2, False)


def test_reset_deactivates_response_faults(server, manifest, injector):
    injector.cross_path(FID, 0, 1)
    assert active_response_faults(server.store, FID, 1).cross_paths == {0: 1}
    injector.reset(FID)
    assert active_response_faults(server.store, FID, 1).cross_paths is None


@pytest.mark.parametrize(
    "call, message",
    [
        (lambda inj: inj.delete(bytes(16), [0]), "no tiene ese archivo"),
        (lambda inj: inj.delete(FID, [0], version=5), "no tiene la versión"),
        (lambda inj: inj.delete(FID, [20]), "fuera de"),
        (lambda inj: inj.delete(FID, []), "al menos un índice"),
        (lambda inj: inj.replace(FID, 3, 3), "sí mismo"),
        (lambda inj: inj.cross_path(FID, 3, 3), "distintos"),
        (lambda inj: inj.rollback(FID, to=1, declare=True), "versión anterior"),
        (lambda inj: inj.damage(FID, 0, DamageOp.DELETE), "ε"),
        (lambda inj: inj.reset(bytes(16)), "no tiene ese archivo"),
    ],
)
def test_invalid_operations(manifest, injector, call, message):
    with pytest.raises(FaultError, match=message):
        call(injector)


def test_modify_of_deleted_block_fails_and_changes_nothing(server, manifest, injector):
    injector.delete(FID, [4])
    before = server.store.block(FID, 1, 3)
    with pytest.raises(FaultError, match="ya no está"):
        injector.modify(FID, [3, 4], seed=1)
    assert server.store.block(FID, 1, 3) == before  # la transacción se deshizo entera
    assert [r[0] for r in _faults(server)] == ["delete"]


def test_dropped_file_rejects_other_operations(manifest, injector):
    injector.drop_file(FID)
    with pytest.raises(FaultError, match="drop-file"):
        injector.delete(FID, [0])


def test_empty_file_cannot_be_damaged(server, injector):
    server.upload(b"")
    with pytest.raises(FaultError, match="vacío"):
        injector.damage(FID, 0.5, DamageOp.DELETE)


# --- CLI ----------------------------------------------------------------------------------------


def _cli(server, *args) -> list[str]:
    return ["--home", str(server.store.home), *args]


def test_cli_delete(server, manifest, capsys):
    assert main(_cli(server, "delete", "--file", to_hex(FID), "--indices", "2", "5")) == 0
    out = capsys.readouterr().out
    assert "delete aplicado" in out and "[2, 5]" in out
    assert server.audit(manifest)[1].status is Status.CORRUPT


def test_cli_prints_generated_seed(server, manifest, capsys):
    args = ["damage", "--file", to_hex(FID), "--eps", "0.1", "--op", "modify"]
    assert main(_cli(server, *args)) == 0
    out = capsys.readouterr().out
    seed = int(out.split("semilla: ")[1])
    assert _faults(server)[0][3] == seed


def test_cli_rollback_requires_declare_or_lie(server, manifest):
    with pytest.raises(SystemExit):
        main(_cli(server, "rollback", "--file", to_hex(FID), "--to", "1"))


def test_cli_reports_fault_errors(server, manifest, capsys):
    assert main(_cli(server, "delete", "--file", to_hex(FID), "--indices", "99")) == 1
    assert "fuera de" in capsys.readouterr().err


def test_cli_rejects_bad_file_id(server, manifest):
    with pytest.raises(SystemExit):
        main(_cli(server, "reset", "--file", "XYZ"))


def test_cli_uses_environment_home(server, manifest, monkeypatch, capsys):
    monkeypatch.setenv("MERKLE_AUDIT_SERVER_HOME", str(server.store.home))
    assert main(["drop-file", "--file", to_hex(FID)]) == 0
    assert server.audit(manifest)[1].status is Status.CORRUPT
    assert main(["reset", "--file", to_hex(FID)]) == 0
    assert server.audit(manifest)[1].status is Status.PASS
