import pytest
from support import to_raw

from merkle_audit.protocol.messages import ErrorMessage
from merkle_audit.protocol.verify import Cause, Status, evaluate_response


def _error(challenge, code, audit_id="same"):
    aid = challenge.audit_id if audit_id == "same" else audit_id
    return to_raw(ErrorMessage(audit_id=aid, code=code).model_dump())


@pytest.mark.parametrize("code", ["UNKNOWN_FILE", "UNKNOWN_VERSION"])
def test_server_admits_loss(store, challenge, code):
    result = evaluate_response(store.manifest, challenge, _error(challenge, code))
    assert result.status is Status.CORRUPT
    assert result.findings[0].cause is Cause.FILE_MISSING
    assert result.server_error_code == code


@pytest.mark.parametrize("code", ["COMMITMENT_MISMATCH", "BAD_REQUEST", "INTERNAL"])
def test_other_server_errors(store, challenge, code):
    result = evaluate_response(store.manifest, challenge, _error(challenge, code))
    assert result.status is Status.INVALID
    assert result.findings[0].cause is Cause.SERVER_ERROR
    assert result.server_error_code == code


def test_error_without_audit_id_is_accepted(store, challenge):
    result = evaluate_response(store.manifest, challenge, _error(challenge, "INTERNAL", None))
    assert result.findings[0].cause is Cause.SERVER_ERROR


def test_error_from_another_audit(store, challenge):
    result = evaluate_response(store.manifest, challenge, _error(challenge, "INTERNAL", "0" * 32))
    assert result.findings[0].cause is Cause.AUDIT_ID_MISMATCH


# --- Contra el servidor real, con el inyector ----------------------------------------------------


def test_dropped_file_is_reported_missing(server, manifest, injector):
    injector.drop_file(manifest.file_id)
    r, result = server.audit(manifest, q=4)
    assert r.status_code == 404 and r.json()["code"] == "UNKNOWN_FILE"
    assert result.status is Status.CORRUPT
    assert result.findings[0].cause is Cause.FILE_MISSING
    injector.reset(manifest.file_id)
    assert server.audit(manifest)[1].status is Status.PASS
