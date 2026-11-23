import random

import pytest
from support import BLOCK, HonestStore, to_raw

from merkle_audit.protocol.challenge import challenge_is_valid, new_challenge, wire_size
from merkle_audit.protocol.messages import Challenge
from merkle_audit.protocol.verify import (
    Cause,
    Status,
    estimate_response_bytes,
    evaluate_response,
    incomplete,
)


@pytest.fixture
def store():
    return HonestStore(bytes(k % 253 for k in range(19 * BLOCK + 1234)))


def _audit(store, msg_or_mutate=None, q=8):
    ch = new_challenge(store.manifest, q)
    msg = store.answer(ch)
    if msg_or_mutate:
        msg_or_mutate(msg, ch)
    return evaluate_response(store.manifest, ch, to_raw(msg)), ch


def test_intact_file_passes(store):
    result, ch = _audit(store)
    assert result.status is Status.PASS
    assert result.findings == []
    assert [e.index for e in result.evidence] == ch.indices
    assert all(e.computed_root == store.tree.root.hex() for e in result.evidence)


def test_full_audit_includes_short_last_block(store):
    result, ch = _audit(store, q=store.manifest.n_blocks)
    assert ch.indices[-1] == store.manifest.n_blocks - 1
    assert result.status is Status.PASS


@pytest.mark.parametrize("size", [1, BLOCK - 1, BLOCK, BLOCK + 1, 3 * BLOCK])
def test_sizes_not_multiple_of_block(size):
    s = HonestStore(bytes(range(256)) * (size // 256) + bytes(size % 256))
    result, _ = _audit(s, q=s.manifest.n_blocks)
    assert result.status is Status.PASS


def test_empty_file_passes_trivially():
    s = HonestStore(b"")
    result, ch = _audit(s, q=0)
    assert ch.indices == []
    assert result.status is Status.PASS
    assert result.trivial


def _set_block(msg, i, block):
    import base64

    msg["proofs"][i]["block"] = base64.b64encode(block).decode()


def test_deleted_block(store):
    def delete(msg, ch):
        msg["proofs"][2].update(block=None, path=[])

    result, ch = _audit(store, delete)
    assert result.status is Status.CORRUPT
    assert [(f.cause, f.index) for f in result.findings] == [(Cause.BLOCK_MISSING, ch.indices[2])]


def test_modified_block(store):
    def modify(msg, ch):
        b = bytearray(store.block(ch.indices[0]))
        b[10] ^= 1
        _set_block(msg, 0, bytes(b))

    result, _ = _audit(store, modify)
    assert result.findings[0].cause is Cause.ROOT_MISMATCH
    assert result.evidence[0].computed_root != store.tree.root.hex()


def test_truncated_block(store):
    def truncate(msg, ch):
        _set_block(msg, 0, store.block(ch.indices[0])[:-1])

    result, _ = _audit(store, truncate)
    assert result.findings[0].cause is Cause.BLOCK_LENGTH


def test_replaced_block(store):
    def replace(msg, ch):
        other = (ch.indices[0] + 1) % (store.manifest.n_blocks - 1)
        _set_block(msg, 0, store.block(other))

    result, _ = _audit(store, replace)
    assert result.findings[0].cause is Cause.ROOT_MISMATCH


def test_cross_path(store):
    def cross(msg, ch):
        other = ch.indices[0] ^ 1
        msg["proofs"][0]["path"] = store.proof_item(other).model_dump()["path"]

    result, _ = _audit(store, cross)
    assert result.findings[0].cause in (Cause.ROOT_MISMATCH, Cause.PATH_LENGTH)


def test_all_failures_are_reported(store):
    def delete_all(msg, ch):
        for p in msg["proofs"]:
            p.update(block=None, path=[])

    result, ch = _audit(store, delete_all)
    assert [f.index for f in result.findings] == ch.indices


def test_incomplete():
    assert incomplete(Cause.TIMEOUT).status is Status.INCOMPLETE
    with pytest.raises(ValueError):
        incomplete(Cause.ROOT_MISMATCH)


def test_challenge_shape(store):
    ch = new_challenge(store.manifest, 10)
    assert len(set(ch.indices)) == 10
    assert ch.indices == sorted(ch.indices)
    assert challenge_is_valid(ch, store.manifest.n_blocks)
    assert wire_size(ch) < 300
    with pytest.raises(ValueError):
        new_challenge(store.manifest, store.manifest.n_blocks + 1)


def test_seeded_challenges_repeat(store):
    a = new_challenge(store.manifest, 5, rng=random.Random(7))  # noqa: S311
    b = new_challenge(store.manifest, 5, rng=random.Random(7))  # noqa: S311
    assert a.indices == b.indices
    assert a.audit_id != b.audit_id


@pytest.mark.parametrize("indices", [[3, 3], [5, 2], [0, 20], [-1], []])
def test_server_side_challenge_validation(store, indices):
    ch = Challenge.model_construct(
        audit_id="0" * 32,
        file_id="0" * 32,
        version=1,
        commitment="0" * 64,
        indices=indices,
    )
    assert not challenge_is_valid(ch, store.manifest.n_blocks)


def test_estimate_close_to_real_size(store):
    ch = new_challenge(store.manifest, 8)
    real = len(to_raw(store.answer(ch)))
    est = estimate_response_bytes(store.manifest, ch.indices)
    assert abs(est - real) / real < 0.05
