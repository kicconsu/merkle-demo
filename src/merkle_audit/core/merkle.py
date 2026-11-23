"""Árbol de Merkle con separación de dominios y pruebas de inclusión.

Cada entrada a SHA-256 empieza con un byte que indica su dominio, y todo entero entra con ancho
fijo (u64). Así ninguna entrada de un tipo puede leerse como otra:

    leaf(i, x)  = H(0x00 ‖ u64(i) ‖ u64(|x|) ‖ x)
    node(l, r)  = H(0x01 ‖ l ‖ r)
    EMPTY_ROOT  = H(0x02 ‖ "empty")
    commit(...) = H(0x03 ‖ file_id ‖ u64(version) ‖ u64(B) ‖ u64(S) ‖ u64(n) ‖ root)

El índice en la hoja impide presentar un bloque en otra posición, y la longitud impide que un
bloque y el mismo con ceros añadidos compartan hoja; por eso el último bloque nunca se rellena.
Un nodo sin hermano se promueve al nivel siguiente sin volver a aplicar el hash. La forma del árbol
depende solo de n, y n queda ligado en el compromiso final junto con el archivo, la versión y los
parámetros (Boneh y Shoup, ejercicio 8.9).
"""

import hashlib
import hmac
from collections.abc import Sequence
from enum import Enum, StrEnum
from typing import BinaryIO

from .encoding import u64
from .params import HASH_SIZE, ID_SIZE

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
EMPTY_PREFIX = b"\x02"
COMMIT_PREFIX = b"\x03"


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


EMPTY_ROOT = _h(EMPTY_PREFIX + b"empty")


def leaf(i: int, x: bytes) -> bytes:
    return _h(LEAF_PREFIX + u64(i) + u64(len(x)) + x)


def node(left: bytes, right: bytes) -> bytes:
    if len(left) != HASH_SIZE or len(right) != HASH_SIZE:
        raise ValueError("los hijos de un nodo deben medir 32 bytes")
    return _h(NODE_PREFIX + left + right)


def commit(
    file_id: bytes, version: int, block_size: int, file_size: int, n: int, root: bytes
) -> bytes:
    """Huella del archivo: liga la raíz con su identidad, su versión y sus parámetros."""
    if len(file_id) != ID_SIZE:
        raise ValueError("file_id debe medir 16 bytes")
    if len(root) != HASH_SIZE:
        raise ValueError("root debe medir 32 bytes")
    return _h(
        COMMIT_PREFIX + file_id + u64(version) + u64(block_size) + u64(file_size) + u64(n) + root
    )


def block_length(i: int, n: int, block_size: int, file_size: int) -> int:
    """Longitud que debe tener el bloque i: block_size, salvo el último, que puede ser corto."""
    if not 0 <= i < n:
        raise ValueError(f"índice {i} fuera de [0, {n})")
    return block_size if i < n - 1 else file_size - (n - 1) * block_size


# --- Construcción -------------------------------------------------------------------------------


class MerkleTree:
    """Árbol completo en memoria: todos los niveles, de las hojas (nivel 0) a la raíz."""

    def __init__(self, leaves: Sequence[bytes]):
        levels = [list(leaves)]
        while len(levels[-1]) > 1:
            cur = levels[-1]
            nxt = [node(cur[k], cur[k + 1]) for k in range(0, len(cur) - 1, 2)]
            if len(cur) % 2 == 1:
                nxt.append(cur[-1])  # nodo sin hermano: se promueve tal cual
            levels.append(nxt)
        self.levels = levels

    @classmethod
    def from_blocks(cls, blocks: Sequence[bytes]) -> "MerkleTree":
        return cls([leaf(i, x) for i, x in enumerate(blocks)])

    @property
    def n(self) -> int:
        return len(self.levels[0])

    @property
    def root(self) -> bytes:
        return self.levels[-1][0] if self.n else EMPTY_ROOT

    def proof(self, i: int) -> list[bytes]:
        """Hashes hermanos de la hoja i hacia la raíz, en el orden de path_shape(i, n)."""
        if not 0 <= i < self.n:
            raise ValueError(f"índice {i} fuera de [0, {self.n})")
        path = []
        idx = i
        for level in self.levels[:-1]:
            sibling = idx ^ 1
            if sibling < len(level):
                path.append(level[sibling])
            idx //= 2
        return path


def _read_block(reader: BinaryIO, size: int) -> bytes:
    """Lee hasta `size` bytes, tolerando lectores que devuelven menos de lo pedido."""
    chunks = []
    missing = size
    while missing:
        chunk = reader.read(missing)
        if not chunk:
            break
        chunks.append(chunk)
        missing -= len(chunk)
    return b"".join(chunks)


def leaves_from_reader(reader: BinaryIO, block_size: int) -> tuple[list[bytes], int]:
    """Calcula las hojas de un archivo leyéndolo bloque a bloque. Devuelve (hojas, tamaño)."""
    if block_size <= 0:
        raise ValueError("block_size debe ser positivo")
    leaves = []
    size = 0
    while block := _read_block(reader, block_size):
        leaves.append(leaf(len(leaves), block))
        size += len(block)
    return leaves, size


# --- Verificación -------------------------------------------------------------------------------


class Side(Enum):
    LEFT = "left"  # el hermano va a la izquierda: node(hermano, actual)
    RIGHT = "right"  # el hermano va a la derecha: node(actual, hermano)


def path_shape(i: int, n: int) -> list[Side]:
    """Lado de cada hermano en el camino de la hoja i, derivado solo de (i, n).

    El verificador nunca toma la dirección del servidor: si lo hiciera, un camino válido de otro
    índice podría hacerse pasar por el de i.
    """
    if not 0 <= i < n:
        raise ValueError(f"índice {i} fuera de [0, {n})")
    shape = []
    idx, width = i, n
    while width > 1:
        if idx % 2 == 1:
            shape.append(Side.LEFT)
        elif idx + 1 < width:
            shape.append(Side.RIGHT)
        # si no, el nodo se promueve en este nivel y no aporta hermano
        idx, width = idx // 2, (width + 1) // 2
    return shape


def root_from_path(i: int, x: bytes, path: Sequence[bytes], n: int) -> bytes:
    """Recalcula la raíz a partir del bloque i y su camino. El camino debe tener la forma exacta."""
    shape = path_shape(i, n)
    if len(path) != len(shape):
        raise ValueError(f"el camino mide {len(path)} y se esperaban {len(shape)} hashes")
    h = leaf(i, x)
    for sibling, side in zip(path, shape, strict=True):
        h = node(sibling, h) if side is Side.LEFT else node(h, sibling)
    return h


class ProofFailure(StrEnum):
    BLOCK_LENGTH = "BLOCK_LENGTH"
    PATH_LENGTH = "PATH_LENGTH"
    ROOT_MISMATCH = "ROOT_MISMATCH"


def verify_block(
    i: int,
    x: bytes,
    path: Sequence[bytes],
    *,
    n: int,
    block_size: int,
    file_size: int,
    root: bytes,
) -> ProofFailure | None:
    """Verifica un bloque contra la raíz confiable. Devuelve None si es válido o la causa del fallo.

    La longitud se comprueba antes de calcular hashes: un bloque truncado se reporta como tal y no
    como un simple desajuste de raíz.
    """
    if len(x) != block_length(i, n, block_size, file_size):
        return ProofFailure.BLOCK_LENGTH
    if len(path) != len(path_shape(i, n)) or any(len(s) != HASH_SIZE for s in path):
        return ProofFailure.PATH_LENGTH
    if not hmac.compare_digest(root_from_path(i, x, path, n), root):
        return ProofFailure.ROOT_MISMATCH
    return None


def tree_for_file(reader: BinaryIO, block_size: int) -> tuple[MerkleTree, int]:
    """Árbol de un archivo leído de `reader`. Devuelve (árbol, tamaño en bytes)."""
    leaves, size = leaves_from_reader(reader, block_size)
    return MerkleTree(leaves), size
