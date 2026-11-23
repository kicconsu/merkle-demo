"""Vectores de prueba fijos del árbol y del compromiso.

Cualquier cambio en la codificación de hojas, nodos o compromiso rompe estos valores.
"""

import io

import pytest

from merkle_audit.core.merkle import EMPTY_ROOT, commit, tree_for_file

FILE_ID = bytes(range(16))
VERSION = 1
BLOCK = 4096

VECTORS = [
    (
        b"",
        0,
        "840850734821db93d0578d224007ed370d3f7e149f1884179cdaa871e154096a",
        "eb445fcec8b6e770cc02516062d3a29b5adbb3b6fb6b70e634a54a8d3aa54441",
    ),
    (
        b"\x00",
        1,
        "b0ef53e122b3c40b579355219695430329f46c3b24936cbd734967780a609be2",
        "a2cace423e09ef46d0cfeba6687a5c806a48a95819bdf58007ee4e8b8722d950",
    ),
    (
        bytes(k % 251 for k in range(2 * BLOCK + 100)),
        3,
        "597db13ae70da526ae336c9f3206e5ad27d734b494436845cdbe78f801500e0f",
        "45cecf6d1b16a5b78797abd66fcf769b69d82513d15160a6cbf4df1adf11bb98",
    ),
]


@pytest.mark.parametrize(("data", "n", "root_hex", "commitment_hex"), VECTORS)
def test_vector(data, n, root_hex, commitment_hex):
    tree, size = tree_for_file(io.BytesIO(data), BLOCK)
    assert size == len(data)
    assert tree.n == n
    assert tree.root.hex() == root_hex
    assert commit(FILE_ID, VERSION, BLOCK, size, n, tree.root).hex() == commitment_hex


def test_empty_root_is_its_own_domain():
    assert EMPTY_ROOT.hex() == VECTORS[0][2]
