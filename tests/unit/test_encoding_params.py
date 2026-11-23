import pytest

from merkle_audit.core.encoding import EncodingError, from_b64, from_hex, to_b64, u64
from merkle_audit.core.params import (
    MAX_FILE_SIZE,
    check_challenge_size,
    check_file_params,
    n_blocks,
)


def test_u64():
    assert u64(1) == b"\x00" * 7 + b"\x01"
    with pytest.raises(ValueError):
        u64(-1)
    with pytest.raises(ValueError):
        u64(2**64)


def test_hex_is_strict():
    assert from_hex("ab" * 16, 16) == b"\xab" * 16
    for bad in ["AB" * 16, "ab" * 15, "ab" * 17, "zz" * 16, " " + "ab" * 16]:
        with pytest.raises(EncodingError):
            from_hex(bad, 16)


def test_b64_is_strict():
    assert from_b64(to_b64(b"\x00\xff")) == b"\x00\xff"
    for bad in ["AA=", "A A=", "AA==\n", "-_=="]:
        with pytest.raises(EncodingError):
            from_b64(bad)


def test_n_blocks():
    assert n_blocks(0, 4096) == 0
    assert n_blocks(1, 4096) == 1
    assert n_blocks(4096, 4096) == 1
    assert n_blocks(4097, 4096) == 2
    assert n_blocks(MAX_FILE_SIZE, 4096) == 128_000


def test_file_params():
    check_file_params(0, 4096)
    check_file_params(MAX_FILE_SIZE, 65536)
    for size, block in [(MAX_FILE_SIZE + 1, 4096), (10, 2048), (10, 5000), (-1, 4096)]:
        with pytest.raises(ValueError):
            check_file_params(size, block)


def test_challenge_size():
    check_challenge_size(0, 0)
    check_challenge_size(1, 1)
    check_challenge_size(1024, 5000)
    for q, n in [(1, 0), (0, 5), (6, 5), (1025, 5000)]:
        with pytest.raises(ValueError):
            check_challenge_size(q, n)
    check_challenge_size(2000, 5000, q_max=2000)
