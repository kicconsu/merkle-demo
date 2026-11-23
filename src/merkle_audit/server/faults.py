"""Inyector de fallos: daña a propósito lo que guarda el servidor, nunca lo que guarda el cliente.

Hay dos clases de fallos:
- **de almacenamiento** (`delete`, `modify`, `replace`, `damage`, `drop-file`): cambian los bloques
  vivos. La copia íntegra no se toca, así que `reset` siempre puede deshacerlos;
- **de respuesta** (`cross-path`, `rollback`): no cambian datos, quedan activos en la tabla `faults`
  y la capa de respuesta (`audit.py`) los consulta al armar cada respuesta.

Cada aplicación queda registrada en `faults` con la operación, los parámetros, la semilla, los
índices afectados y la hora. Las operaciones aleatorias usan `random.Random(seed)`: con la misma
semilla, el mismo daño. Este generador no es criptográfico a propósito: aquí se busca repetir un
experimento, no que el daño sea impredecible.
"""

import json
import random
import secrets
import sqlite3
from dataclasses import dataclass
from enum import StrEnum

from ..core.probability import damaged_blocks
from .store import Store, VersionInfo, now_utc


class FaultError(Exception):
    """La operación no se puede aplicar (archivo, versión o índice inexistente, por ejemplo)."""


class ModifyMode(StrEnum):
    BITFLIP = "bitflip"
    TRUNCATE = "truncate"


class DamageOp(StrEnum):
    DELETE = "delete"
    MODIFY = "modify"


@dataclass(frozen=True)
class Applied:
    """Resultado de una operación: lo que se hizo, para mostrarlo y para los tests."""

    op: str
    file_id: bytes
    version: int | None
    indices: list[int]
    seed: int | None = None
    fault_id: int | None = None


@dataclass(frozen=True)
class ResponseFaults:
    """Fallos de respuesta activos para una versión."""

    rollback_to: int | None = None
    declare: bool = False
    cross_paths: dict[int, int] | None = None  # índice → índice cuyo camino se entrega


def new_seed() -> int:
    return secrets.randbits(32)


class Injector:
    def __init__(self, store: Store):
        self.store = store

    # --- Utilidades -----------------------------------------------------------------------------

    def _target(self, file_id: bytes, version: int | None) -> VersionInfo:
        """La versión sobre la que se actúa (la última si no se indica), comprobando que exista."""
        versions = self.store.versions(file_id)
        if not versions:
            raise FaultError("el servidor no tiene ese archivo")
        v = versions[-1] if version is None else version
        info = self.store.version_info(file_id, v)
        if info is None:
            raise FaultError(f"el archivo no tiene la versión {v}; hay {versions}")
        if info.dropped:
            raise FaultError("el archivo fue borrado con drop-file; usa reset primero")
        return info

    @staticmethod
    def _check_indices(info: VersionInfo, indices: list[int]) -> list[int]:
        if not indices:
            raise FaultError("hace falta al menos un índice")
        bad = [i for i in indices if not 0 <= i < info.n_blocks]
        if bad:
            raise FaultError(f"índices fuera de [0, {info.n_blocks}): {bad}")
        return sorted(set(indices))

    @staticmethod
    def _log(
        conn: sqlite3.Connection,
        op: str,
        file_id: bytes,
        version: int | None,
        params: dict,
        indices: list[int],
        seed: int | None = None,
        active: bool = False,
    ) -> int:
        cur = conn.execute(
            "INSERT INTO faults (file_id, version, op, params, seed, indices, applied_at, active) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                file_id,
                version,
                op,
                json.dumps(params, sort_keys=True),
                seed,
                json.dumps(indices),
                now_utc(),
                int(active),
            ),
        )
        return cur.lastrowid

    @staticmethod
    def _live_block(conn: sqlite3.Connection, info: VersionInfo, i: int) -> bytes:
        row = conn.execute(
            "SELECT data FROM blocks WHERE file_id = ? AND version = ? AND idx = ?",
            (info.file_id, info.version, i),
        ).fetchone()
        if row is None:
            raise FaultError(f"el bloque {i} ya no está (fue borrado)")
        return row[0]

    @staticmethod
    def _set_block(conn: sqlite3.Connection, info: VersionInfo, i: int, data: bytes) -> None:
        conn.execute(
            "UPDATE blocks SET data = ? WHERE file_id = ? AND version = ? AND idx = ?",
            (data, info.file_id, info.version, i),
        )

    # --- Fallos de almacenamiento ---------------------------------------------------------------

    def delete(self, file_id: bytes, indices: list[int], version: int | None = None) -> Applied:
        info = self._target(file_id, version)
        indices = self._check_indices(info, indices)
        with self.store.connect() as conn:
            self._delete(conn, info, indices)
            fid = self._log(conn, "delete", file_id, info.version, {}, indices)
        return Applied("delete", file_id, info.version, indices, fault_id=fid)

    @staticmethod
    def _delete(conn: sqlite3.Connection, info: VersionInfo, indices: list[int]) -> None:
        conn.executemany(
            "DELETE FROM blocks WHERE file_id = ? AND version = ? AND idx = ?",
            [(info.file_id, info.version, i) for i in indices],
        )

    def modify(
        self,
        file_id: bytes,
        indices: list[int],
        mode: ModifyMode = ModifyMode.BITFLIP,
        seed: int | None = None,
        version: int | None = None,
    ) -> Applied:
        info = self._target(file_id, version)
        indices = self._check_indices(info, indices)
        seed = new_seed() if seed is None else seed
        with self.store.connect() as conn:
            self._modify(conn, info, indices, ModifyMode(mode), random.Random(seed))  # noqa: S311
            fid = self._log(conn, "modify", file_id, info.version, {"mode": mode}, indices, seed)
        return Applied("modify", file_id, info.version, indices, seed, fid)

    def _modify(
        self,
        conn: sqlite3.Connection,
        info: VersionInfo,
        indices: list[int],
        mode: ModifyMode,
        rng: random.Random,
    ) -> None:
        for i in indices:
            x = bytearray(self._live_block(conn, info, i))
            if mode is ModifyMode.TRUNCATE:
                del x[-1]
            else:
                bit = rng.randrange(len(x) * 8)
                x[bit // 8] ^= 1 << (bit % 8)
            self._set_block(conn, info, i, bytes(x))

    def replace(self, file_id: bytes, i: int, j: int, version: int | None = None) -> Applied:
        """El bloque i pasa a tener el contenido del bloque j."""
        info = self._target(file_id, version)
        self._check_indices(info, [i, j])
        if i == j:
            raise FaultError("reemplazar un bloque por sí mismo no cambia nada")
        with self.store.connect() as conn:
            self._set_block(conn, info, i, self._live_block(conn, info, j))
            fid = self._log(conn, "replace", file_id, info.version, {"with": j}, [i])
        return Applied("replace", file_id, info.version, [i], fault_id=fid)

    def damage(
        self,
        file_id: bytes,
        eps: float,
        op: DamageOp,
        mode: ModifyMode = ModifyMode.BITFLIP,
        seed: int | None = None,
        version: int | None = None,
    ) -> Applied:
        """Daña d = ⌈ε·n⌉ bloques elegidos al azar con la semilla."""
        info = self._target(file_id, version)
        if not 0 < eps <= 1:
            raise FaultError("ε debe estar en (0, 1]")
        d = damaged_blocks(info.n_blocks, eps)
        if d == 0:
            raise FaultError("el archivo está vacío: no hay bloques que dañar")
        seed = new_seed() if seed is None else seed
        rng = random.Random(seed)  # noqa: S311
        indices = sorted(rng.sample(range(info.n_blocks), d))
        op = DamageOp(op)
        params: dict = {"eps": eps, "op": op, "d": d}
        with self.store.connect() as conn:
            if op is DamageOp.DELETE:
                self._delete(conn, info, indices)
            else:
                params["mode"] = mode
                self._modify(conn, info, indices, ModifyMode(mode), rng)
            fid = self._log(conn, "damage", file_id, info.version, params, indices, seed)
        return Applied("damage", file_id, info.version, indices, seed, fid)

    def drop_file(self, file_id: bytes) -> Applied:
        """Borra los bloques vivos de todas las versiones. La copia íntegra queda para `reset`."""
        if not self.store.versions(file_id):
            raise FaultError("el servidor no tiene ese archivo")
        with self.store.connect() as conn:
            conn.execute("DELETE FROM blocks WHERE file_id = ?", (file_id,))
            conn.execute("UPDATE versions SET dropped = 1 WHERE file_id = ?", (file_id,))
            fid = self._log(conn, "drop-file", file_id, None, {}, [])
        return Applied("drop-file", file_id, None, [], fault_id=fid)

    def reset(self, file_id: bytes) -> Applied:
        """Vuelve al estado de la carga: bloques de la copia íntegra y sin fallos de respuesta."""
        if not self.store.versions(file_id):
            raise FaultError("el servidor no tiene ese archivo")
        with self.store.connect() as conn:
            conn.execute("DELETE FROM blocks WHERE file_id = ?", (file_id,))
            conn.execute(
                "INSERT INTO blocks SELECT file_id, version, idx, data FROM pristine "
                "WHERE file_id = ?",
                (file_id,),
            )
            conn.execute("UPDATE versions SET dropped = 0 WHERE file_id = ?", (file_id,))
            conn.execute("UPDATE faults SET active = 0 WHERE file_id = ?", (file_id,))
            fid = self._log(conn, "reset", file_id, None, {}, [])
        return Applied("reset", file_id, None, [], fault_id=fid)

    # --- Fallos de respuesta --------------------------------------------------------------------

    def cross_path(self, file_id: bytes, i: int, j: int, version: int | None = None) -> Applied:
        """Al responder por el índice i, el servidor entrega el camino de j."""
        info = self._target(file_id, version)
        self._check_indices(info, [i, j])
        if i == j:
            raise FaultError("el camino cruzado necesita dos índices distintos")
        with self.store.connect() as conn:
            fid = self._log(
                conn, "cross-path", file_id, info.version, {"with": j}, [i], active=True
            )
        return Applied("cross-path", file_id, info.version, [i], fault_id=fid)

    def rollback(
        self, file_id: bytes, to: int, declare: bool, version: int | None = None
    ) -> Applied:
        """Responde a la versión v con los datos de v' < v, declarando v' o mintiendo con v."""
        info = self._target(file_id, version)
        if not 1 <= to < info.version:
            raise FaultError(f"la versión anterior debe estar en [1, {info.version})")
        params = {"to": to, "declare": declare}
        with self.store.connect() as conn:
            conn.execute(  # un rollback nuevo reemplaza al anterior de la misma versión
                "UPDATE faults SET active = 0 "
                "WHERE file_id = ? AND version = ? AND op = 'rollback'",
                (file_id, info.version),
            )
            fid = self._log(conn, "rollback", file_id, info.version, params, [], active=True)
        return Applied("rollback", file_id, info.version, [], fault_id=fid)


def active_response_faults(store: Store, file_id: bytes, version: int) -> ResponseFaults:
    """Fallos de respuesta activos para (file_id, version); el más reciente manda."""
    with store.connect() as conn:
        rows = conn.execute(
            "SELECT op, params, indices FROM faults "
            "WHERE file_id = ? AND version = ? AND active = 1 ORDER BY id",
            (file_id, version),
        ).fetchall()
    rollback_to, declare, cross = None, False, {}
    for op, params, indices in rows:
        p = json.loads(params)
        if op == "rollback":
            rollback_to, declare = p["to"], p["declare"]
        elif op == "cross-path":
            cross[json.loads(indices)[0]] = p["with"]
    return ResponseFaults(rollback_to, declare, cross or None)
