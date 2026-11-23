"""El panel arranca sin excepciones, vacío y con datos, y una auditoría desde la interfaz queda
registrada. Sin servidor encendido: el panel lo avisa en la barra lateral.
"""

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from merkle_audit.client.auditlog import AuditLog
from merkle_audit.client.storage import ClientHome
from merkle_audit.core.encoding import to_hex
from merkle_audit.core.manifest import Manifest
from merkle_audit.core.merkle import tree_for_file

APP = Path(__file__).parents[2] / "src" / "merkle_audit" / "ui" / "app.py"


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    # el panel toma directorio y servidor de las variables de entorno
    monkeypatch.setenv("MERKLE_AUDIT_HOME", str(tmp_path / "h"))
    monkeypatch.setenv("MERKLE_AUDIT_SERVER", "http://127.0.0.1:9")  # nadie escucha


def _run() -> AppTest:
    at = AppTest.from_file(str(APP), default_timeout=30)
    return at.run()


def test_empty_home_renders():
    at = _run()
    assert not at.exception
    assert any("Aún no hay archivos" in i.value for i in at.sidebar.info)
    assert any("Sin respuesta del servidor" in e.value for e in at.sidebar.error)
    assert len(at.tabs) == 5


@pytest.fixture
def seeded(tmp_path):
    """Manifiesto local sin servidor: alcanza para pintar el panel; auditar dará INCOMPLETE."""
    import io

    home = ClientHome(tmp_path / "h")
    tree, size = tree_for_file(io.BytesIO(bytes(range(256)) * 400), 4096)
    m = Manifest.create(
        file_id=bytes(range(16)),
        version=1,
        file_name="demo.bin",
        file_size=size,
        block_size=4096,
        root=tree.root,
    )
    home.save_manifest(m)
    return home, m


def test_renders_manifest_and_metrics(seeded):
    home, m = seeded
    at = _run()
    assert not at.exception
    assert any(to_hex(m.root) in c.value for c in at.code)
    assert any("Bloques (n)" == x.label for x in at.metric)


def test_audit_button_logs_an_incomplete_audit_without_server(seeded):
    home, m = seeded
    at = _run()
    next(b for b in at.button if b.label == "Auditar ahora").click()
    at.run()
    assert not at.exception
    rows = AuditLog(home.db_path).list_audits()
    assert len(rows) == 1 and rows[0]["status"] == "INCOMPLETE"
    assert any("INCOMPLETE" in w.value for w in at.warning)
