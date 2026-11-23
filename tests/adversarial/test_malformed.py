import pytest
from support import to_raw

from merkle_audit.protocol.verify import Cause, Status, evaluate_response


def _set(key, value):
    return lambda m: m.update({key: value})


def _proof(key, value):
    return lambda m: m["proofs"][0].update({key: value})


MUTATIONS = {
    "protocolo desconocido": _set("protocol", "merkle-audit/2"),
    "tipo desconocido": _set("type", "respuesta"),
    "campo extra": _set("extra", 1),
    "falta un campo": lambda m: m.pop("version"),
    "versión como texto": _set("version", "1"),
    "versión booleana": _set("version", True),
    "audit_id en mayúsculas": lambda m: m.update(audit_id=m["audit_id"].upper()),
    "índice negativo": _proof("index", -1),
    "bloque no base64": _proof("block", "no es base64!"),
    "bloque como lista": _proof("block", [1, 2]),
    "hash corto en el camino": _proof("path", ["ab" * 31]),
    "hash en mayúsculas": _proof("path", ["AB" * 32]),
    "campo extra en la prueba": _proof("side", "left"),
}


@pytest.mark.parametrize("mutate", MUTATIONS.values(), ids=MUTATIONS.keys())
def test_malformed_response(store, challenge, mutate):
    msg = store.answer(challenge)
    mutate(msg)
    result = evaluate_response(store.manifest, challenge, to_raw(msg))
    assert result.status is Status.INVALID
    assert result.findings[0].cause is Cause.MALFORMED


@pytest.mark.parametrize("raw", [b"", b"no json", b"[]", b"null", b'{"type": 3}', b"\xff\xfe"])
def test_not_a_message(store, challenge, raw):
    result = evaluate_response(store.manifest, challenge, raw)
    assert result.status is Status.INVALID
    assert result.findings[0].cause is Cause.MALFORMED
