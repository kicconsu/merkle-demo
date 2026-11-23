"""El servidor responde por un índice con el camino de otro."""

import pytest
from support import findings

from merkle_audit.core.merkle import path_shape
from merkle_audit.protocol.verify import Cause, Status

N = 20


@pytest.mark.parametrize("i, j", [(0, 1), (2, 3), (4, 12), (0, 19), (19, 0), (16, 18)])
def test_cross_path_is_detected(server, manifest, injector, i, j):
    injector.cross_path(manifest.file_id, i, j)
    result = server.audit(manifest, indices=sorted({i, j}))[1]
    same_length = len(path_shape(i, N)) == len(path_shape(j, N))
    expected = Cause.ROOT_MISMATCH if same_length else Cause.PATH_LENGTH
    assert result.status is Status.CORRUPT
    assert findings(result) == [(i, expected)]


def test_both_causes_appear_in_a_20_block_file():
    # n = 20 no es potencia de dos: los caminos no miden todos lo mismo
    assert len(path_shape(0, N)) != len(path_shape(19, N))
    assert len(path_shape(0, N)) == len(path_shape(1, N))


def test_reset_disables_cross_path(server, manifest, injector):
    injector.cross_path(manifest.file_id, 0, 1)
    injector.reset(manifest.file_id)
    assert server.audit(manifest)[1].status is Status.PASS
