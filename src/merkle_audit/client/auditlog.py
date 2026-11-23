"""Bitácora de auditorías y programas, en SQLite (`client.db`).

`audits` es solo de inserción: dos triggers impiden UPDATE y DELETE, de modo que lo registrado no
se reescribe por accidente. No se guarda contenido de bloques ni la clave; solo hojas y raíces
recomputadas, que bastan para explicar el resultado.
"""

import json
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audits (
    audit_id TEXT PRIMARY KEY,
    file_id TEXT NOT NULL, version INTEGER NOT NULL, commitment TEXT,
    protocol TEXT NOT NULL, package_version TEXT NOT NULL,
    n INTEGER, q INTEGER, block_size INTEGER, file_size INTEGER,
    timeout_s REAL NOT NULL, origin TEXT NOT NULL,
    indices TEXT NOT NULL,
    status TEXT NOT NULL, trivial INTEGER NOT NULL, findings TEXT NOT NULL,
    server_error_code TEXT,
    evidence TEXT NOT NULL, response_sha256 TEXT,
    started_at TEXT NOT NULL, finished_at TEXT NOT NULL, latency_ms REAL,
    challenge_bytes INTEGER, response_bytes INTEGER, verify_ms REAL,
    theory TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audits_no_update BEFORE UPDATE ON audits
BEGIN SELECT RAISE(ABORT, 'audits es solo de insercion'); END;
CREATE TRIGGER IF NOT EXISTS audits_no_delete BEFORE DELETE ON audits
BEGIN SELECT RAISE(ABORT, 'audits es solo de insercion'); END;
CREATE TABLE IF NOT EXISTS schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id TEXT NOT NULL, every_s REAL NOT NULL,
    q INTEGER, target_eps REAL, confidence REAL,
    timeout_s REAL NOT NULL, created_at TEXT NOT NULL, last_run_at TEXT
);
"""

AUDIT_COLUMNS = (
    "audit_id file_id version commitment protocol package_version n q block_size file_size "
    "timeout_s origin indices status trivial findings server_error_code evidence response_sha256 "
    "started_at finished_at latency_ms challenge_bytes response_bytes verify_ms theory"
).split()
_JSON_COLUMNS = {"indices", "findings", "evidence", "theory"}


@dataclass(frozen=True)
class Schedule:
    id: int
    file_id: str
    every_s: float
    q: int | None
    target_eps: float | None
    confidence: float | None
    timeout_s: float
    created_at: str
    last_run_at: str | None


class AuditLog:
    def __init__(self, db_path: str | Path):
        self.path = Path(db_path)
        with closing(self._connect()) as db:
            db.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        return db

    # --- auditorías ----------------------------------------------------------------------------

    def add_audit(self, record: dict) -> None:
        """Inserta una fila; `record` trae exactamente las columnas (campos JSON como objetos)."""
        if set(record) != set(AUDIT_COLUMNS):
            raise ValueError(f"columnas inesperadas: {set(record) ^ set(AUDIT_COLUMNS)}")
        values = [
            json.dumps(record[c], sort_keys=True) if c in _JSON_COLUMNS else record[c]
            for c in AUDIT_COLUMNS
        ]
        marks = ", ".join("?" for _ in AUDIT_COLUMNS)
        with closing(self._connect()) as db, db:
            db.execute(
                f"INSERT INTO audits ({', '.join(AUDIT_COLUMNS)}) VALUES ({marks})",  # noqa: S608
                values,
            )

    def get_audit(self, audit_id: str) -> dict | None:
        with closing(self._connect()) as db:
            row = db.execute("SELECT * FROM audits WHERE audit_id = ?", (audit_id,)).fetchone()
        return _decode(row) if row else None

    def list_audits(self, file_id: str | None = None, limit: int = 20) -> list[dict]:
        """Las más recientes primero."""
        sql, args = "SELECT * FROM audits", []
        if file_id:
            sql += " WHERE file_id = ?"
            args.append(file_id)
        sql += " ORDER BY started_at DESC, rowid DESC LIMIT ?"
        args.append(limit)
        with closing(self._connect()) as db:
            return [_decode(r) for r in db.execute(sql, args)]

    # --- programas -----------------------------------------------------------------------------

    def add_schedule(
        self,
        *,
        file_id: str,
        every_s: float,
        q: int | None,
        target_eps: float | None,
        confidence: float | None,
        timeout_s: float,
        created_at: str,
    ) -> int:
        with closing(self._connect()) as db, db:
            cur = db.execute(
                "INSERT INTO schedules (file_id, every_s, q, target_eps, confidence, timeout_s,"
                " created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (file_id, every_s, q, target_eps, confidence, timeout_s, created_at),
            )
            return int(cur.lastrowid)

    def list_schedules(self) -> list[Schedule]:
        with closing(self._connect()) as db:
            return [Schedule(**dict(r)) for r in db.execute("SELECT * FROM schedules ORDER BY id")]

    def remove_schedule(self, schedule_id: int) -> bool:
        with closing(self._connect()) as db, db:
            return db.execute("DELETE FROM schedules WHERE id = ?", (schedule_id,)).rowcount > 0

    def mark_schedule_run(self, schedule_id: int, when: str) -> None:
        with closing(self._connect()) as db, db:
            db.execute("UPDATE schedules SET last_run_at = ? WHERE id = ?", (when, schedule_id))


def _decode(row: sqlite3.Row) -> dict:
    out = dict(row)
    for k in _JSON_COLUMNS:
        out[k] = json.loads(out[k])
    out["trivial"] = bool(out["trivial"])
    return out
