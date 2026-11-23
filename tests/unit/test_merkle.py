import io
import math

import pytest
from hypothesis import given
from hypothesis import strategies as st

from merkle_audit.core.merkle import (
    EMPTY_ROOT,
    MerkleTree,
    ProofFailure,
    Side,
    block_length,
    commit,
    leaf,
    node,
    path_shape,
    root_from_path,
    tree_for_file,
    verify_block,
)

blocks_st = st.lists(st.binary(min_size=1, max_size=8), min_size=1, max_size=300)


@given(blocks_st)
def test_every_proof_verifies(blocks):
    tree = MerkleTree.from_blocks(blocks)
    for i, x in enumerate(blocks):
        assert root_from_path(i, x, tree.proof(i), tree.n) == tree.root


@given(st.integers(min_value=1, max_value=5000), st.data())
def test_path_length_is_at_most_log2(n, data):
    i = data.draw(st.integers(min_value=0, max_value=n - 1))
    bound = math.ceil(math.log2(n)) if n > 1 else 0
    assert len(path_shape(i, n)) <= bound


@given(blocks_st, st.data())
def test_modified_block_fails(blocks, data):
    tree = MerkleTree.from_blocks(blocks)
    i = data.draw(st.integers(min_value=0, max_value=tree.n - 1))
    bad = bytes([blocks[i][0] ^ 1]) + blocks[i][1:]
    assert root_from_path(i, bad, tree.proof(i), tree.n) != tree.root


@given(blocks_st, st.data())
def test_block_presented_at_another_index_fails(blocks, data):
    tree = MerkleTree.from_blocks(blocks)
    if tree.n < 2:
        return
    i, j = data.draw(st.lists(st.integers(0, tree.n - 1), min_size=2, max_size=2, unique=True))
    path = tree.proof(j)
    if len(path) == len(path_shape(i, tree.n)):
        assert root_from_path(i, blocks[j], path, tree.n) != tree.root


def test_shape_with_promoted_node():
    # n = 3: la hoja 2 no tiene hermano en el nivel 0 y sube sola
    assert path_shape(0, 3) == [Side.RIGHT, Side.RIGHT]
    assert path_shape(1, 3) == [Side.LEFT, Side.RIGHT]
    assert path_shape(2, 3) == [Side.LEFT]
    blocks = [b"a", b"b", b"c"]
    expected = node(node(leaf(0, b"a"), leaf(1, b"b")), leaf(2, b"c"))
    assert MerkleTree.from_blocks(blocks).root == expected


def test_single_block_tree():
    tree = MerkleTree.from_blocks([b"x"])
    assert tree.root == leaf(0, b"x")
    assert tree.proof(0) == []


def test_empty_tree():
    tree = MerkleTree([])
    assert tree.n == 0
    assert tree.root == EMPTY_ROOT


def test_leaf_binds_index_and_length():
    assert leaf(0, b"ab") != leaf(1, b"ab")
    assert leaf(0, b"ab") != leaf(0, b"ab\x00")


def test_leaf_and_node_domains_differ():
    left, right = leaf(0, b"a"), leaf(1, b"b")
    # una hoja cuyo contenido imita la entrada de un nodo no da el mismo hash
    assert node(left, right) != leaf(0, left + right)


def test_zero_padding_changes_root():
    data = b"\x01" * 5000
    padded = data + b"\x00" * (8192 - len(data))
    a, _ = tree_for_file(io.BytesIO(data), 4096)
    b, _ = tree_for_file(io.BytesIO(padded), 4096)
    assert a.root != b.root


def test_block_length():
    assert block_length(0, 3, 4096, 8292) == 4096
    assert block_length(2, 3, 4096, 8292) == 100
    assert block_length(0, 1, 4096, 4096) == 4096
    with pytest.raises(ValueError):
        block_length(3, 3, 4096, 8292)


class _ShortReader(io.RawIOBase):
    """Lector que entrega como máximo 7 bytes por llamada."""

    def __init__(self, data):
        self._buf = io.BytesIO(data)

    def read(self, size=-1):
        return self._buf.read(min(size, 7) if size and size > 0 else 7)


def test_reader_with_short_reads():
    data = bytes(range(256)) * 40
    a, size = tree_for_file(_ShortReader(data), 4096)
    b, _ = tree_for_file(io.BytesIO(data), 4096)
    assert size == len(data)
    assert a.root == b.root


# --- verify_block ---


@pytest.fixture
def file3():
    data = bytes(k % 251 for k in range(2 * 4096 + 100))
    tree, size = tree_for_file(io.BytesIO(data), 4096)
    blocks = [data[i * 4096 : (i + 1) * 4096] for i in range(tree.n)]
    params = {"n": tree.n, "block_size": 4096, "file_size": size, "root": tree.root}
    return tree, blocks, params


def test_verify_block_ok(file3):
    tree, blocks, params = file3
    for i, x in enumerate(blocks):
        assert verify_block(i, x, tree.proof(i), **params) is None


def test_verify_block_truncated(file3):
    tree, blocks, params = file3
    assert verify_block(2, blocks[2][:-1], tree.proof(2), **params) is ProofFailure.BLOCK_LENGTH


def test_verify_block_wrong_path_length(file3):
    tree, blocks, params = file3
    path = tree.proof(0)[:-1]
    assert verify_block(0, blocks[0], path, **params) is ProofFailure.PATH_LENGTH


def test_verify_block_bad_sibling_size(file3):
    tree, blocks, params = file3
    path = [tree.proof(0)[0][:-1], tree.proof(0)[1]]
    assert verify_block(0, blocks[0], path, **params) is ProofFailure.PATH_LENGTH


def test_verify_block_cross_path(file3):
    tree, blocks, params = file3
    # el camino de la hoja 1 tiene la misma longitud que el de la 0, pero no sirve para ella
    assert verify_block(0, blocks[0], tree.proof(1), **params) is ProofFailure.ROOT_MISMATCH


def test_verify_block_replaced(file3):
    tree, blocks, params = file3
    assert verify_block(0, blocks[1], tree.proof(0), **params) is ProofFailure.ROOT_MISMATCH


def test_commit_binds_every_field():
    fid, root = bytes(16), bytes(32)
    base = commit(fid, 1, 4096, 100, 1, root)
    variants = [
        commit(bytes([1]) + bytes(15), 1, 4096, 100, 1, root),
        commit(fid, 2, 4096, 100, 1, root),
        commit(fid, 1, 8192, 100, 1, root),
        commit(fid, 1, 4096, 101, 1, root),
        commit(fid, 1, 4096, 100, 2, root),
        commit(fid, 1, 4096, 100, 1, bytes([1]) + bytes(31)),
    ]
    assert len({base, *variants}) == 7
