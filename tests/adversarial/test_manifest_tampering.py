"""Un manifiesto alterado se rechaza antes de enviar el desafío."""

import json

import pytest

from merkle_audit.core.manifest import ManifestError, compute_mac, dumps, loads
from merkle_audit.protocol.verify import Cause, Status, manifest_rejected

KEY = bytes(32)


def _result(text):
    with pytest.raises(ManifestError) as e:
        loads(text, KEY)
    return manifest_rejected(e.value)


def test_altered_root(store):
    fields = json.loads(dumps(store.manifest, KEY))
    fields["root"] = "00" * 32
    result = _result(json.dumps(fields))
    assert result.status is Status.INVALID
    assert result.findings[0].cause is Cause.MANIFEST_MAC


def test_altered_root_with_forged_mac(store):
    # sin la clave el MAC no se puede rehacer; con la clave, el compromiso sigue delatando el cambio
    fields = json.loads(dumps(store.manifest, KEY))
    fields["root"] = "00" * 32
    fields["mac"] = compute_mac(KEY, fields).hex()
    assert _result(json.dumps(fields)).findings[0].cause is Cause.MANIFEST_COMMITMENT


def test_corrupted_file(store):
    assert _result("{").findings[0].cause is Cause.MANIFEST_FORMAT
