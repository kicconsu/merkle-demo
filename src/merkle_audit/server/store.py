"""Almacén del servidor: una base SQLite con bloques, niveles del árbol y copia íntegra.

Al cargar una versión se guardan tres cosas:
- los bloques vivos (`blocks`), que son los que el servidor entrega y los que el inyector daña;
- una copia íntegra de los mismos bloques (`pristine`), para que el inyector pueda deshacer el daño;
- los niveles del árbol (`levels`), de los que salen los caminos de inclusión.

Los caminos nunca se recalculan a partir de los bloques vivos. Si un bloque se altera, su camino
sigue siendo el de la carga y el cliente ve que la raíz no coincide.
"""

import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from ..core.merkle import MerkleTree, commit, leaf
from ..core.params import HASH_SIZE, ID_SIZE, check_file_params, n_blocks

HOME_ENV = "MERKLE_AUDIT_SERVER_HOME"
DEFAULT_HOME = ".merkle-audit-server"
DB_NAME = "server.db"

_CHUNK = 1 << 20  # lectura del cuerpo de la carga por trozos de 1 MiB

_SCHEMA = """
CREATE TABLE IF NOT EXISTS versions (
    file_id     BLOB    NOT NULL,
    version     INTEGER NOT NULL,
    block_size  INTEGER NOT NULL,
    file_size   INTEGER NOT NULL,
    n_blocks    INTEGER NOT NULL,
    root        BLOB    NOT NULL,
    commitment  BLOB    NOT NULL,
    created_at  TEXT    NOT NULL,
    dropped     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (file_id, version)
);
CREATE TABLE IF NOT EXISTS blocks (
    file_id BLOB    NOT NULL,
    version INTEGER NOT NULL,
    idx     INTEGER NOT NULL,
    data    BLOB    NOT NULL,
    PRIMARY KEY (file_id, version, idx)
);
CREATE TABLE IF NOT EXISTS pristine (
    file_id BLOB    NOT NULL,
    version INTEGER NOT NULL,
    idx     INTEGER NOT NULL,
    data    BLOB    NOT NULL,
    PRIMARY KEY (file_id, version, idx)
);
CREATE TABLE IF NOT EXISTS levels (
    file_id BLOB    NOT NULL,
    version INTEGER NOT NULL,
    level   INTEGER NOT NULL,
    hashes  BLOB    NOT NULL,
    PRIMARY KEY (file_id, version, level)
);
CREATE TABLE IF NOT EXISTS faults (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id    BLOB    NOT NULL,
    version    INTEGER,
    op         TEXT    NOT NULL,
    params     TEXT    NOT NULL,
    seed       INTEGER,
    indices    TEXT    NOT NULL,
    applied_at TEXT    NOT NULL,
    active     INTEGER NOT NULL DEFAULT 0
);
"""


class StoreError(Exception):
    """Error de una operación del almacén."""


class VersionExists(StoreError):
    """La versión ya está cargada: las versiones son inmutables."""


class VersionOutOfOrder(StoreError):
    """La versión no es la última cargada + 1."""


class SizeMismatch(StoreError):
    """El cuerpo de la carga no mide lo que se declaró."""


@dataclass(frozen=True)
class VersionInfo:
    file_id: bytes
    version: int
    block_size: int
    file_size: int
    n_blocks: int
    root: bytes
    commitment: bytes
    created_at: str
    dropped: bool


class StoredTree:
    """Niveles del árbol de una versión, tal como quedaron en la carga."""

    def __init__(self, levels: list[bytes]):
        self._levels = levels

    @property
    def n(self) -> int:
        return len(self._levels[0]) // HASH_SIZE if self._levels else 0

    def path(self, i: int) -> list[bytes]:
        """Hashes hermanos de la hoja i hacia la raíz, en el orden de path_shape(i, n)."""
        if not 0 <= i < self.n:
            raise ValueError(f"índice {i} fuera de [0, {self.n})")
        path = []
        idx = i
        for level in self._levels[:-1]:
            sibling = idx ^ 1
            if sibling * HASH_SIZE < len(level):
                path.append(level[sibling * HASH_SIZE : (sibling + 1) * HASH_SIZE])
            idx //= 2
        return path


def default_home() -> Path:
    return Path(os.environ.get(HOME_ENV, DEFAULT_HOME))


def now_utc() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _check_id(file_id: bytes) -> None:
    if len(file_id) != ID_SIZE:
        raise ValueError(f"file_id debe medir {ID_SIZE} bytes")


class Store:
    def __init__(self, home: Path | str | None = None):
        self.home = Path(home) if home is not None else default_home()
        self.home.mkdir(parents=True, exist_ok=True)
        self.db_path = self.home / DB_NAME
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")  # el inyector escribe con el servidor encendido
            conn.executescript(_SCHEMA)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Conexión con una transacción: confirma al salir sin error, deshace si hay excepción."""
        conn = sqlite3.connect(self.db_path, timeout=30)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    # --- Carga ----------------------------------------------------------------------------------

    def put_version(
        self, file_id: bytes, version: int, block_size: int, file_size: int, reader: BinaryIO
    ) -> VersionInfo:
        """Guarda una versión leyendo exactamente `file_size` bytes de `reader`.

        Todo ocurre en una transacción: si algo falla, no queda rastro de la versión.
        """
        _check_id(file_id)
        check_file_params(file_size, block_size)
        if version < 1:
            raise VersionOutOfOrder("la versión empieza en 1")

        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")  # serializa cargas concurrentes del mismo archivo
            if self._row(conn, file_id, version) is not None:
                raise VersionExists(f"la versión {version} ya existe")
            last = conn.execute(
                "SELECT MAX(version) FROM versions WHERE file_id = ?", (file_id,)
            ).fetchone()[0]
            expected = (last or 0) + 1
            if version != expected:
                raise VersionOutOfOrder(f"se esperaba la versión {expected}, llegó {version}")

            leaves = self._store_blocks(conn, file_id, version, block_size, file_size, reader)
            tree = MerkleTree(leaves)
            n = tree.n
            for k, level in enumerate(tree.levels):
                conn.execute(
                    "INSERT INTO levels VALUES (?, ?, ?, ?)",
                    (file_id, version, k, b"".join(level)),
                )
            info = VersionInfo(
                file_id=file_id,
                version=version,
                block_size=block_size,
                file_size=file_size,
                n_blocks=n,
                root=tree.root,
                commitment=commit(file_id, version, block_size, file_size, n, tree.root),
                created_at=now_utc(),
                dropped=False,
            )
            conn.execute(
                "INSERT INTO versions VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)",
                (
                    file_id,
                    version,
                    block_size,
                    file_size,
                    n,
                    info.root,
                    info.commitment,
                    info.created_at,
                ),
            )
        return info

    def _store_blocks(
        self,
        conn: sqlite3.Connection,
        file_id: bytes,
        version: int,
        block_size: int,
        file_size: int,
        reader: BinaryIO,
    ) -> list[bytes]:
        leaves: list[bytes] = []
        buf = bytearray()
        total = 0

        def flush(data: bytes) -> None:
            i = len(leaves)
            row = (file_id, version, i, data)
            conn.execute("INSERT INTO blocks VALUES (?, ?, ?, ?)", row)
            conn.execute("INSERT INTO pristine VALUES (?, ?, ?, ?)", row)
            leaves.append(leaf(i, data))

        while chunk := reader.read(_CHUNK):
            total += len(chunk)
            if total > file_size:
                raise SizeMismatch(f"el cuerpo mide más de los {file_size} bytes declarados")
            buf += chunk
            while len(buf) >= block_size:
                flush(bytes(buf[:block_size]))
                del buf[:block_size]
        if total != file_size:
            raise SizeMismatch(f"el cuerpo mide {total} bytes y se declararon {file_size}")
        if buf:
            flush(bytes(buf))
        assert len(leaves) == n_blocks(file_size, block_size)
        return leaves

    # --- Consulta -------------------------------------------------------------------------------

    @staticmethod
    def _row(conn: sqlite3.Connection, file_id: bytes, version: int) -> VersionInfo | None:
        row = conn.execute(
            "SELECT * FROM versions WHERE file_id = ? AND version = ?", (file_id, version)
        ).fetchone()
        if row is None:
            return None
        *fields, dropped = row
        return VersionInfo(*fields, dropped=bool(dropped))

    def version_info(self, file_id: bytes, version: int) -> VersionInfo | None:
        with self.connect() as conn:
            return self._row(conn, file_id, version)

    def versions(self, file_id: bytes) -> list[int]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT version FROM versions WHERE file_id = ? ORDER BY version", (file_id,)
            ).fetchall()
        return [v for (v,) in rows]

    def latest_version(self, file_id: bytes) -> int | None:
        versions = self.versions(file_id)
        return versions[-1] if versions else None

    def is_dropped(self, file_id: bytes) -> bool:
        """True si el archivo existe y fue borrado por completo (todas sus versiones)."""
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT dropped FROM versions WHERE file_id = ?", (file_id,)
            ).fetchall()
        return bool(rows) and all(d for (d,) in rows)

    def block(self, file_id: bytes, version: int, i: int) -> bytes | None:
        """El bloque vivo i, o None si no está (borrado por el inyector o fuera de rango)."""
        with self.connect() as conn:
            row = conn.execute(
                "SELECT data FROM blocks WHERE file_id = ? AND version = ? AND idx = ?",
                (file_id, version, i),
            ).fetchone()
        return None if row is None else row[0]

    def blocks(self, file_id: bytes, version: int, indices: list[int]) -> dict[int, bytes]:
        """Los bloques vivos pedidos que existen, en una sola consulta por tanda."""
        found: dict[int, bytes] = {}
        with self.connect() as conn:
            for start in range(0, len(indices), 500):  # límite de parámetros de SQLite
                part = indices[start : start + 500]
                marks = ",".join("?" * len(part))
                rows = conn.execute(
                    f"SELECT idx, data FROM blocks WHERE file_id = ? AND version = ? "  # noqa: S608
                    f"AND idx IN ({marks})",
                    (file_id, version, *part),
                ).fetchall()
                found.update(rows)
        return found

    def tree(self, file_id: bytes, version: int) -> StoredTree:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT hashes FROM levels WHERE file_id = ? AND version = ? ORDER BY level",
                (file_id, version),
            ).fetchall()
        return StoredTree([h for (h,) in rows])
