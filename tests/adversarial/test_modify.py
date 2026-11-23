"""Bloques alterados en el almacenamiento: un bit invertido o un byte de menos."""

import pytest
from support import DATA_20, findings

from merkle_audit.protocol.verify import Cause, Status
from merkle_audit.server.faults import ModifyMode


@pytest.mark.parametrize("seed", range(5))
def test_bitflip_breaks_the_root(server, manifest, injector, seed):
    injector.modify(manifest.file_id, [4, 19], ModifyMode.BITFLIP, seed=seed)
    result = server.audit(manifest, indices=[3, 4, 19])[1]
    assert result.status is Status.CORRUPT
    assert findings(result) == [(4, Cause.ROOT_MISMATCH), (19, Cause.ROOT_MISMATCH)]


def test_bitflip_changes_exactly_one_bit(server, manifest, injector):
    before = server.store.block(manifest.file_id, 1, 6)
    injector.modify(manifest.file_id, [6], ModifyMode.BITFLIP, seed=123)
    after = server.store.block(manifest.file_id, 1, 6)
    assert len(after) == len(before)
    assert sum(bin(a ^ b).count("1") for a, b in zip(before, after, strict=True)) == 1


def test_truncate_is_a_length_failure(server, manifest, injector):
    injector.modify(manifest.file_id, [0, 19], ModifyMode.TRUNCATE)
    result = server.audit(manifest, indices=[0, 19])[1]
    assert result.status is Status.CORRUPT
    assert findings(result) == [(0, Cause.BLOCK_LENGTH), (19, Cause.BLOCK_LENGTH)]


def test_same_seed_same_damage(tmp_path):
    from support import ServerHarness

    from merkle_audit.server.faults import Injector

    blocks = []
    for name in ("a", "b"):
        server = ServerHarness(tmp_path / name)
        manifest = server.upload(DATA_20)
        Injector(server.store).modify(manifest.file_id, [5], seed=99)
        blocks.append(server.store.block(manifest.file_id, 1, 5))
    assert blocks[0] == blocks[1]
