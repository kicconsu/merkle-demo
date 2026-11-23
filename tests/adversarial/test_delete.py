"""Bloques borrados del almacenamiento: el servidor los declara con `block: null`."""

from support import findings

from merkle_audit.protocol.verify import Cause, Status


def test_deleted_blocks_are_declared_missing(server, manifest, injector):
    injector.delete(manifest.file_id, [2, 7])
    r, result = server.audit(manifest, indices=[1, 2, 7, 19])
    assert [p["block"] is None for p in r.json()["proofs"]] == [False, True, True, False]
    assert result.status is Status.CORRUPT
    assert findings(result) == [(2, Cause.BLOCK_MISSING), (7, Cause.BLOCK_MISSING)]


def test_audit_that_misses_the_deleted_blocks_passes(server, manifest, injector):
    # una auditoría solo dice algo de los índices que consultó
    injector.delete(manifest.file_id, [2, 7])
    assert server.audit(manifest, indices=[0, 1, 3, 19])[1].status is Status.PASS


def test_full_audit_finds_every_deleted_block(server, manifest, injector):
    injector.delete(manifest.file_id, [0, 10, 19])
    result = server.audit(manifest)[1]
    assert {i for i, _ in findings(result)} == {0, 10, 19}


def test_reset_restores_deleted_blocks(server, manifest, injector):
    injector.delete(manifest.file_id, list(range(20)))
    assert server.audit(manifest)[1].status is Status.CORRUPT
    injector.reset(manifest.file_id)
    assert server.audit(manifest)[1].status is Status.PASS
