from support import to_raw

from merkle_audit.protocol.challenge import new_challenge
from merkle_audit.protocol.verify import Cause, Status, evaluate_response


def test_response_to_previous_audit_is_rejected(store, challenge):
    old = store.answer(challenge)
    fresh = new_challenge(store.manifest, 8)
    # aunque los índices coincidieran, el audit_id de la respuesta vieja no es el del desafío nuevo
    old["proofs"] = store.answer(fresh)["proofs"]
    result = evaluate_response(store.manifest, fresh, to_raw(old))
    assert result.status is Status.INVALID
    assert result.findings[0].cause is Cause.AUDIT_ID_MISMATCH


def test_challenges_are_fresh(store):
    a, b = new_challenge(store.manifest, 8), new_challenge(store.manifest, 8)
    assert a.audit_id != b.audit_id
