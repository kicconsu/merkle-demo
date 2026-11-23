from support import HonestStore, to_raw

from merkle_audit.protocol.verify import Cause, Status, evaluate_response


def test_response_for_another_file_is_rejected(store, challenge):
    other = HonestStore(store.data, file_id=bytes(16))
    msg = other.answer(challenge)
    msg["file_id"] = other.manifest.file_id.hex()
    result = evaluate_response(store.manifest, challenge, to_raw(msg))
    assert result.status is Status.INVALID
    assert result.findings[0].cause is Cause.FILE_ID_MISMATCH


def test_blocks_of_another_file_fail_the_root(store, challenge):
    other = HonestStore(bytes(len(store.data)))  # mismo tamaño, otro contenido
    result = evaluate_response(store.manifest, challenge, to_raw(other.answer(challenge)))
    assert result.status is Status.CORRUPT
    assert {f.cause for f in result.findings} == {Cause.ROOT_MISMATCH}
