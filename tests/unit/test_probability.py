import pytest
from hypothesis import given
from hypothesis import strategies as st

from merkle_audit.core.probability import (
    approx_with_replacement,
    damaged_blocks,
    detection_probability,
    detection_probability_exact,
    min_challenge_size,
    miss_probability_repeated,
    wilson_interval,
)


@st.composite
def ndq(draw, max_n=400):
    n = draw(st.integers(1, max_n))
    return n, draw(st.integers(0, n)), draw(st.integers(0, n))


@given(ndq())
def test_float_matches_exact(args):
    assert detection_probability(*args) == pytest.approx(
        float(detection_probability_exact(*args)), abs=1e-12
    )


@pytest.mark.parametrize(
    ("n", "d", "q", "expected"),
    [
        (10_000, 100, 100, 0.635805),
        (10_000, 100, 300, 0.953175),
        (10_000, 100, 460, 0.991202),
        (10_000, 500, 50, 0.923551),
    ],
)
def test_reference_table(n, d, q, expected):
    assert detection_probability(n, d, q) == pytest.approx(expected, abs=1e-6)


def test_exact_is_above_with_replacement():
    # sin reemplazo nunca se repite un índice, así que detecta al menos tanto como con reemplazo
    assert detection_probability(10_000, 100, 100) > approx_with_replacement(0.01, 100)


def test_edges():
    assert detection_probability(10, 0, 5) == 0.0
    assert detection_probability(10, 3, 0) == 0.0
    assert detection_probability(10, 3, 8) == 1.0
    assert detection_probability(10, 10, 1) == 1.0
    assert detection_probability(10, 1, 1) == pytest.approx(0.1)
    with pytest.raises(ValueError):
        detection_probability(10, 11, 1)
    with pytest.raises(ValueError):
        detection_probability(10, 1, 11)


@given(ndq(max_n=200))
def test_monotone_in_q(args):
    n, d, q = args
    if q < n:
        assert detection_probability(n, d, q + 1) >= detection_probability(n, d, q)


def test_min_challenge_size_reference():
    # la aproximación con reemplazo pediría 459; la fórmula exacta necesita menos
    assert min_challenge_size(10_000, 100, 0.99) == 448


@given(st.integers(2, 300), st.data(), st.floats(0.01, 0.999))
def test_min_challenge_size_is_minimal(n, data, conf):
    d = data.draw(st.integers(1, n))
    q = min_challenge_size(n, d, conf)
    assert detection_probability(n, d, q) >= conf
    assert q == 1 or detection_probability(n, d, q - 1) < conf


def test_min_challenge_size_rejects_no_damage():
    with pytest.raises(ValueError):
        min_challenge_size(100, 0, 0.99)


def test_damaged_blocks_rounding():
    assert damaged_blocks(100, 0.07) == 7
    assert damaged_blocks(10_000, 0.01) == 100
    assert damaged_blocks(7, 0.25) == 2
    assert damaged_blocks(100, 0) == 0


def test_repeated_audits():
    p = detection_probability(1000, 10, 50)
    assert miss_probability_repeated(1000, 10, 50, 3) == pytest.approx((1 - p) ** 3)
    assert miss_probability_repeated(1000, 10, 50, 0) == 1.0


def test_wilson_interval():
    lo, hi = wilson_interval(636, 1000, 0.99)
    assert lo < 0.636 < hi
    assert lo < 0.635805 < hi
    assert hi - lo < 0.1
    assert wilson_interval(0, 50)[0] == 0.0
    assert wilson_interval(50, 50)[1] == 1.0


@pytest.mark.parametrize("trials", [1, 7, 100, 1000, 12345])
def test_wilson_extremes_are_exact(trials):
    assert wilson_interval(trials, trials)[1] == 1.0
    assert wilson_interval(0, trials)[0] == 0.0
