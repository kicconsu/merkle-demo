"""Cliente de punta a punta contra el servidor real (FastAPI + SQLite) con el inyector de fallos."""

import json
import os
import sqlite3
import sys
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient
from support import BLOCK, DATA_20

from merkle_audit.client.auditlog import AuditLog
from merkle_audit.client.auditor import UploadError, reverify, run_audit, upload_file
from merkle_audit.client.cli import main
from merkle_audit.client.scheduler import add_schedule, parse_every, run_due
from merkle_audit.client.storage import ClientHome, UnknownManifest
from merkle_audit.client.transport import HttpTransport
from merkle_audit.core.encoding import to_hex
from merkle_audit.protocol.verify import Cause, Status
from merkle_audit.server.app import create_app
from merkle_audit.server.faults import Injector
from merkle_audit.server.store import Store


class Env:
    def __init__(self, tmp_path):
        self.store = Store(tmp_path / "server")
        self.http = TestClient(create_app(self.store))
        self.transport = HttpTransport(client=self.http)
        self.home = ClientHome(tmp_path / "client")
        self.log = AuditLog(self.home.db_path)
        self.injector = Injector(self.store)
        self.dir = tmp_path

    def file(self, data: bytes, name: str = "datos.bin"):
        path = self.dir / name
        path.write_bytes(data)
        return path

    def upload(self, data: bytes = DATA_20, **kw):
        return upload_file(self.home, self.transport, self.file(data), **kw)

    def audit(self, manifest, **kw):
        kw.setdefault("q", manifest.n_blocks)
        return run_audit(self.home, self.log, self.transport, manifest.file_id, **kw)


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


# --- Carga y auditoría --------------------------------------------------------------------------


@pytest.mark.parametrize("size", [0, 1, BLOCK, 3 * BLOCK + 17])
def test_upload_then_audit_passes(env, size):
    m = env.upload(bytes(k % 251 for k in range(size)))
    rec = env.audit(m, q=m.n_blocks)
    assert rec.result.status is Status.PASS
    assert rec.result.trivial == (size == 0)


def test_new_version_increments_and_audits_latest(env):
    m1 = env.upload()
    m2 = env.upload(DATA_20[:5000], file_id=m1.file_id)
    assert (m1.version, m2.version) == (1, 2)
    assert env.home.versions(m1.file_id) == [1, 2]
    rec = env.audit(m2, q=2)
    assert rec.version == 2 and rec.result.status is Status.PASS
    assert env.audit(m1, version=1, q=5).result.status is Status.PASS


def test_client_does_not_keep_the_file_or_leak_the_key(env):
    m = env.upload()
    assert DATA_20[:64] not in b"".join(p.read_bytes() for p in env.home.root.rglob("*.json"))
    env.audit(m, q=5)
    key = env.home.key()
    assert key not in env.home.db_path.read_bytes()
    assert key not in b"".join(p.read_bytes() for p in env.home.root.rglob("manifests/**/*.json"))


@pytest.mark.skipif(sys.platform == "win32", reason="permisos POSIX")
def test_key_file_is_private(env):
    env.home.key()
    assert env.home.key_path.stat().st_mode & 0o777 == 0o600


def test_receipt_mismatch_leaves_no_manifest(env):
    class Lying(HttpTransport):
        def upload(self, *a, **kw):
            status, raw = super().upload(*a, **kw)
            body = json.loads(raw)
            body["root"] = "0" * 64
            return status, json.dumps(body).encode()

    with pytest.raises(UploadError, match="no coincide"):
        upload_file(env.home, Lying(client=env.http), env.file(DATA_20))
    assert env.home.file_ids() == []


def test_server_rejection_is_reported(env):
    m = env.upload()
    with pytest.raises(UploadError):  # versión 2 ya existe en el servidor, pero no en local
        env.home_file = env.file(b"x")
        # se fuerza la colisión: el cliente cree que va por la 1 y el servidor ya la tiene
        for p in (env.home.root / "manifests" / to_hex(m.file_id)).glob("*.json"):
            p.unlink()
        upload_file(env.home, env.transport, env.home_file, file_id=m.file_id)


# --- Detección y bitácora -----------------------------------------------------------------------


def test_corruption_is_detected_and_logged(env):
    m = env.upload()
    env.injector.delete(m.file_id, [3])
    env.injector.modify(m.file_id, [9])
    rec = env.audit(m, q=20)
    assert rec.result.status is Status.CORRUPT
    assert {(f.index, f.cause) for f in rec.result.findings} == {
        (3, Cause.BLOCK_MISSING),
        (9, Cause.ROOT_MISMATCH),
    }
    row = env.log.get_audit(rec.audit_id)
    assert row["status"] == "CORRUPT" and row["indices"] == list(range(20))
    assert {e["index"]: e["cause"] for e in row["evidence"] if e["cause"]} == {
        3: "BLOCK_MISSING",
        9: "ROOT_MISMATCH",
    }
    assert row["origin"] == "manual" and row["protocol"] == "merkle-audit/1"
    assert row["challenge_bytes"] > 0 and row["response_bytes"] > 0 and row["verify_ms"] >= 0
    assert set(row["theory"]) == {"1%", "5%", "10%", "25%"}


def test_dropped_file_is_corrupt_file_missing(env):
    m = env.upload()
    env.injector.drop_file(m.file_id)
    rec = env.audit(m, q=4)
    assert rec.result.status is Status.CORRUPT
    assert rec.result.findings[0].cause is Cause.FILE_MISSING


def test_audit_log_is_append_only(env):
    m = env.upload()
    rec = env.audit(m, q=3)
    db = sqlite3.connect(env.home.db_path)
    with pytest.raises(sqlite3.DatabaseError, match="solo de insercion"):
        db.execute("UPDATE audits SET status = 'PASS'")
    with pytest.raises(sqlite3.DatabaseError, match="solo de insercion"):
        db.execute("DELETE FROM audits")
    db.close()
    assert env.log.get_audit(rec.audit_id) is not None


def test_each_audit_uses_a_fresh_id_and_indices(env):
    m = env.upload()
    a, b = env.audit(m, q=8), env.audit(m, q=8)
    assert a.audit_id != b.audit_id
    assert a.row["indices"] != b.row["indices"]  # 1 contra C(20,8) = 125970


def test_default_q_targets_one_percent_at_99(env):
    m = env.upload()
    rec = run_audit(env.home, env.log, env.transport, m.file_id)  # sin q
    assert rec.row["q"] == min(m.n_blocks, 20)  # n = 20: hace falta consultar casi todo


# --- Manifiesto alterado: no se envía el desafío ------------------------------------------------


def test_tampered_manifest_is_invalid_and_sends_nothing(env):
    m = env.upload()
    path = env.home.root / "manifests" / to_hex(m.file_id) / "1.json"
    doc = json.loads(path.read_text())
    doc["root"] = "ab" * 32
    path.write_text(json.dumps(doc))

    sent = []

    def handler(request):
        sent.append(request)
        return httpx.Response(500)

    t = HttpTransport(
        client=httpx.Client(transport=httpx.MockTransport(handler), base_url="http://x")
    )
    rec = run_audit(env.home, env.log, t, m.file_id, q=3)
    assert rec.result.status is Status.INVALID
    assert rec.result.findings[0].cause is Cause.MANIFEST_MAC
    assert sent == []
    assert env.log.get_audit(rec.audit_id)["status"] == "INVALID"


def test_unknown_file_has_no_manifest(env):
    with pytest.raises(UnknownManifest):
        run_audit(env.home, env.log, env.transport, bytes(16), q=1)


# --- INCOMPLETE ---------------------------------------------------------------------------------


def _mock(handler):
    return HttpTransport(
        client=httpx.Client(transport=httpx.MockTransport(handler), base_url="http://x")
    )


@pytest.mark.parametrize(
    ("handler", "cause"),
    [
        (lambda r: (_ for _ in ()).throw(httpx.ReadTimeout("lento")), Cause.TIMEOUT),
        (lambda r: (_ for _ in ()).throw(httpx.ConnectError("caído")), Cause.CONNECTION),
        (lambda r: httpx.Response(502, content=b""), Cause.CONNECTION),
    ],
)
def test_no_answer_is_incomplete_not_evidence(env, handler, cause):
    m = env.upload()
    rec = run_audit(env.home, env.log, _mock(handler), m.file_id, q=5)
    assert rec.result.status is Status.INCOMPLETE
    assert rec.result.findings[0].cause is cause
    assert env.log.get_audit(rec.audit_id)["status"] == "INCOMPLETE"


def test_garbage_body_is_malformed(env):
    m = env.upload()
    rec = run_audit(
        env.home, env.log, _mock(lambda r: httpx.Response(200, content=b"hola")), m.file_id, q=5
    )
    assert rec.result.status is Status.INVALID
    assert rec.result.findings[0].cause is Cause.MALFORMED


# --- reverify -----------------------------------------------------------------------------------


def test_reverify_repeats_the_verdict_from_the_saved_response(env):
    m = env.upload()
    env.injector.modify(m.file_id, [4])
    rec = env.audit(m, q=20, keep_responses=True)
    again = reverify(env.home, env.log, rec.audit_id)
    assert again.status is rec.result.status is Status.CORRUPT
    assert [(f.index, f.cause) for f in again.findings] == [(4, Cause.ROOT_MISMATCH)]
    assert again.response_sha256 == rec.result.response_sha256


def test_reverify_needs_a_kept_response(env):
    m = env.upload()
    rec = env.audit(m, q=3)
    with pytest.raises(FileNotFoundError):
        reverify(env.home, env.log, rec.audit_id)
    with pytest.raises(KeyError):
        reverify(env.home, env.log, "0" * 32)


# --- Programador --------------------------------------------------------------------------------


def test_parse_every():
    assert parse_every("30s") == 30 and parse_every("10m") == 600 and parse_every("2h") == 7200
    for bad in ("0m", "10", "m", "-5s", "1w", ""):
        with pytest.raises(ValueError):
            parse_every(bad)


def test_schedule_runs_when_due_and_records_origin(env):
    m = env.upload()
    sid = add_schedule(env.log, file_id=to_hex(m.file_id), every="10m", q=4)
    now = datetime.now(UTC).timestamp()
    assert run_due(env.home, env.log, env.transport, now=now) == []  # aún no vence
    records = run_due(env.home, env.log, env.transport, now=now + 601)
    assert len(records) == 1 and records[0].row["origin"] == f"schedule:{sid}"
    assert records[0].row["q"] == 4
    # la ejecución quedó anotada con la hora real: no vence hasta dentro de otro intervalo
    assert run_due(env.home, env.log, env.transport, now=now + 5) == []
    later = (datetime.now(UTC) + timedelta(minutes=11)).timestamp()
    assert len(run_due(env.home, env.log, env.transport, now=later)) == 1


def test_schedule_with_target_eps_picks_q(env):
    m = env.upload()
    add_schedule(env.log, file_id=to_hex(m.file_id), every="1s", target_eps=0.25, confidence=0.9)
    rec = run_due(env.home, env.log, env.transport, now=datetime.now(UTC).timestamp() + 5)[0]
    assert 1 <= rec.row["q"] < 20


def test_schedule_validation(env):
    fid = to_hex(bytes(16))
    with pytest.raises(ValueError):
        add_schedule(env.log, file_id=fid, every="5m", q=3, target_eps=0.1)
    with pytest.raises(ValueError):
        add_schedule(env.log, file_id=fid, every="5m", target_eps=2)


# --- CLI ----------------------------------------------------------------------------------------


def test_cli_end_to_end(tmp_path, capsys, monkeypatch):
    env = Env(tmp_path)
    # el CLI crea su propio transporte; se le entrega el del TestClient
    monkeypatch.setattr("merkle_audit.client.cli.HttpTransport", lambda url: env.transport)
    monkeypatch.setattr(env.transport, "close", lambda: None)
    base = ["--home", str(env.home.root)]
    path = env.file(DATA_20)

    assert main([*base, "upload", str(path)]) == 0
    fid = env.home.file_ids()[0]
    fid_hex = to_hex(fid)
    assert fid_hex in capsys.readouterr().out

    assert main([*base, "audit", "--file-id", fid_hex, "--q", "10"]) == 0
    assert "PASS" in capsys.readouterr().out

    env.injector.delete(fid, list(range(20)))
    assert main([*base, "audit", "--file-id", fid_hex, "--q", "3", "--keep-responses"]) == 1
    out = capsys.readouterr().out
    assert "CORRUPT" in out and "BLOCK_MISSING" in out
    audit_id = env.log.list_audits(limit=1)[0]["audit_id"]

    assert main([*base, "reverify", audit_id]) == 1
    assert main([*base, "log"]) == 0
    assert audit_id in capsys.readouterr().out

    assert main([*base, "audit", "--file-id", fid_hex, "--q", "999"]) == 64
    assert main([*base, "audit", "--file-id", "zz"]) == 64
    assert main([*base, "audit", "--file-id", to_hex(bytes(16))]) == 64
    assert "error:" in capsys.readouterr().err

    assert main([*base, "schedule", "add", "--file-id", fid_hex, "--every", "1s", "--q", "2"]) == 0
    assert main([*base, "schedule", "list"]) == 0
    assert main([*base, "schedule", "remove", "1"]) == 0
    assert main([*base, "schedule", "remove", "1"]) == 64


def test_home_defaults_to_env(tmp_path, monkeypatch):
    monkeypatch.setenv("MERKLE_AUDIT_HOME", str(tmp_path / "h"))
    assert ClientHome().root == tmp_path / "h"
    assert os.path.isdir(tmp_path / "h")
