import pytest
from support import to_raw

from merkle_audit.protocol.verify import Cause, Status, evaluate_response


def _missing(msg, store, ch):
    msg["proofs"].pop()


def _extra(msg, store, ch):
    extra = next(i for i in range(store.manifest.n_blocks) if i not in ch.indices)
    msg["proofs"].append(store.proof_item(extra).model_dump())


def _duplicate(msg, store, ch):
    msg["proofs"][-1] = msg["proofs"][0]


def _foreign(msg, store, ch):
    foreign = next(i for i in range(store.manifest.n_blocks) if i not in ch.indices)
    msg["proofs"][0] = store.proof_item(foreign).model_dump()


def _reordered(msg, store, ch):
    msg["proofs"].reverse()


def _empty(msg, store, ch):
    msg["proofs"] = []


@pytest.mark.parametrize("mutate", [_missing, _extra, _duplicate, _foreign, _reordered, _empty])
def test_index_set_must_match(store, challenge, mutate):
    msg = store.answer(challenge)
    mutate(msg, store, challenge)
    result = evaluate_response(store.manifest, challenge, to_raw(msg))
    assert result.status is Status.INVALID
    assert result.findings[0].cause is Cause.INDEX_SET_MISMATCH
    assert result.evidence == []  # no se verifica ninguna prueba de una respuesta no ligada
