import json

import pytest

from merkle_audit.core.manifest import (
    Manifest,
    ManifestError,
    ManifestFailure,
    compute_mac,
    dumps,
    loads,
    new_key,
)

KEY = bytes(range(32))


def _manifest(**over):
    args = {
        "file_id": bytes(range(16)),
        "version": 1,
        "file_name": "datos.bin",
        "file_size": 8292,
        "block_size": 4096,
        "root": bytes(32),
        "created_at": "2026-11-18T20:15:00Z",
    }
    args.update(over)
    return Manifest.create(**args)


def _resealed(fields):
    """Vuelve a calcular el MAC con la clave correcta tras editar los campos."""
    fields["mac"] = compute_mac(KEY, fields).hex()
    return json.dumps(fields)


def _failure(text, key=KEY):
    with pytest.raises(ManifestError) as e:
        loads(text, key)
    return e.value.failure


def test_roundtrip():
    m = _manifest()
    assert m.n_blocks == 3
    assert loads(dumps(m, KEY), KEY) == m


def test_empty_file():
    m = _manifest(file_size=0)
    assert m.n_blocks == 0
    assert loads(dumps(m, KEY), KEY) == m


def test_canonical_mac_ignores_formatting():
    fields = json.loads(dumps(_manifest(), KEY))
    compact = json.dumps(fields, separators=(",", ":"))
    assert loads(compact, KEY) == _manifest()


@pytest.mark.parametrize(
    ("field", "value"),
    [("version", 2), ("file_size", 8291), ("root", "11" * 32), ("file_name", "otro.bin")],
)
def test_tampered_field_fails_mac(field, value):
    fields = json.loads(dumps(_manifest(), KEY))
    fields[field] = value
    assert _failure(json.dumps(fields)) is ManifestFailure.MANIFEST_MAC


def test_wrong_key_fails_mac():
    assert _failure(dumps(_manifest(), KEY), new_key()) is ManifestFailure.MANIFEST_MAC


@pytest.mark.parametrize(
    "mutate",
    [
        lambda f: f.pop("root"),
        lambda f: f.update(extra=1),
        lambda f: f.update(version=True),
        lambda f: f.update(file_size=8292.0),
        lambda f: f.update(format_version=2),
        lambda f: f.update(root="AB" * 32),
        lambda f: f.update(file_id="00" * 15),
    ],
)
def test_malformed_fields(mutate):
    fields = json.loads(dumps(_manifest(), KEY))
    mutate(fields)
    assert _failure(json.dumps(fields)) is ManifestFailure.MANIFEST_FORMAT


def test_not_json():
    assert _failure("{no es json") is ManifestFailure.MANIFEST_FORMAT
    assert _failure("[]") is ManifestFailure.MANIFEST_FORMAT


def test_inconsistent_n_with_valid_mac():
    fields = json.loads(dumps(_manifest(), KEY))
    fields["n_blocks"] = 4
    assert _failure(_resealed(fields)) is ManifestFailure.MANIFEST_FORMAT


def test_bad_block_size_with_valid_mac():
    fields = json.loads(dumps(_manifest(), KEY))
    fields["block_size"] = 5000
    fields["n_blocks"] = 2
    assert _failure(_resealed(fields)) is ManifestFailure.MANIFEST_FORMAT


def test_wrong_commitment_with_valid_mac():
    fields = json.loads(dumps(_manifest(), KEY))
    fields["root"] = "11" * 32
    assert _failure(_resealed(fields)) is ManifestFailure.MANIFEST_COMMITMENT


def test_create_rejects_bad_params():
    with pytest.raises(ValueError):
        _manifest(block_size=1000)
    with pytest.raises(ValueError):
        _manifest(file_size=-1)
    with pytest.raises(ValueError):
        _manifest(version=0)
