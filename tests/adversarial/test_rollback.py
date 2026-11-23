from support import DATA_20, HonestStore, to_raw

from merkle_audit.protocol.challenge import new_challenge
from merkle_audit.protocol.verify import Cause, Status, evaluate_response


def _versions(store):
    v1 = store
    v2 = HonestStore(bytes(reversed(store.data)), version=2)
    return v1, v2


def test_declared_rollback_is_rejected(store):
    v1, v2 = _versions(store)
    challenge = new_challenge(v2.manifest, 8)
    msg = v1.answer(challenge)
    msg["version"] = 1  # el servidor responde con la versión vieja y lo dice
    result = evaluate_response(v2.manifest, challenge, to_raw(msg))
    assert result.status is Status.INVALID
    assert result.findings[0].cause is Cause.VERSION_MISMATCH


def test_undeclared_rollback_fails_the_root(store):
    v1, v2 = _versions(store)
    challenge = new_challenge(v2.manifest, 8)
    msg = v1.answer(challenge)  # etiqueta la versión 2, pero los datos son de la 1
    result = evaluate_response(v2.manifest, challenge, to_raw(msg))
    assert result.status is Status.CORRUPT
    assert {f.cause for f in result.findings} == {Cause.ROOT_MISMATCH}


# --- Contra el servidor real, con el inyector ----------------------------------------------------


def _two_versions(server, manifest):
    return server.upload(bytes(reversed(DATA_20)), version=2)


def test_server_declared_rollback(server, manifest, injector):
    v2 = _two_versions(server, manifest)
    injector.rollback(v2.file_id, to=1, declare=True)
    r, result = server.audit(v2, q=8)
    assert r.json()["version"] == 1
    assert result.status is Status.INVALID
    assert result.findings[0].cause is Cause.VERSION_MISMATCH


def test_server_lies_about_the_version(server, manifest, injector):
    v2 = _two_versions(server, manifest)
    injector.rollback(v2.file_id, to=1, declare=False)
    r, result = server.audit(v2, q=8)
    assert r.json()["version"] == 2
    assert result.status is Status.CORRUPT
    assert {f.cause for f in result.findings} == {Cause.ROOT_MISMATCH}


def test_rollback_to_a_shorter_version(server, manifest, injector):
    # la versión vieja tiene 20 bloques y la nueva 39: lo que no existe en v1 va como block: null
    v2 = server.upload(DATA_20 + DATA_20, version=2)
    injector.rollback(v2.file_id, to=1, declare=False)
    result = server.audit(v2, indices=[0, 25, 38])[1]
    assert result.status is Status.CORRUPT
    causes = {f.index: f.cause for f in result.findings}
    assert causes[25] is Cause.BLOCK_MISSING and causes[38] is Cause.BLOCK_MISSING
    assert causes[0] is Cause.PATH_LENGTH  # el árbol de v1 es menos profundo que el de v2


def test_old_version_is_still_audited_honestly(server, manifest, injector):
    v2 = _two_versions(server, manifest)
    injector.rollback(v2.file_id, to=1, declare=False)
    assert server.audit(manifest)[1].status is Status.PASS  # el fallo es solo sobre v2
    injector.reset(v2.file_id)
    assert server.audit(v2)[1].status is Status.PASS
