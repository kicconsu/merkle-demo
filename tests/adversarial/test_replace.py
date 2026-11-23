"""Un bloque reemplazado por otro bloque auténtico del mismo archivo."""

from support import findings

from merkle_audit.protocol.verify import Cause, Status


def test_replaced_block_fails_the_root(server, manifest, injector):
    # el bloque 5 pasa a ser una copia del 6: es un bloque auténtico, pero no el de la posición 5
    injector.replace(manifest.file_id, 5, 6)
    assert server.store.block(manifest.file_id, 1, 5) == server.store.block(manifest.file_id, 1, 6)
    result = server.audit(manifest, indices=[5, 6])[1]
    assert result.status is Status.CORRUPT
    assert findings(result) == [(5, Cause.ROOT_MISMATCH)]


def test_identical_blocks_do_not_collide(tmp_path):
    # aun si dos bloques tienen el mismo contenido, la hoja liga el índice: leaf(i, x) ≠ leaf(j, x)
    from support import BLOCK, ServerHarness

    from merkle_audit.server.faults import Injector

    server = ServerHarness(tmp_path)
    manifest = server.upload(b"A" * BLOCK * 4)
    Injector(server.store).replace(manifest.file_id, 1, 2)
    assert server.audit(manifest)[1].status is Status.PASS  # mismo contenido: nada cambió
