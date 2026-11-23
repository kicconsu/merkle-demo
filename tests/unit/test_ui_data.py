"""Cálculos del panel: curvas de detección y costo, y resúmenes de la bitácora."""

import io

import pytest

from merkle_audit.core.manifest import Manifest
from merkle_audit.core.merkle import tree_for_file
from merkle_audit.core.probability import damaged_blocks, detection_probability
from merkle_audit.ui import data


def _manifest(size: int, block: int = 4096) -> Manifest:
    tree, size = tree_for_file(io.BytesIO(bytes(size)), block)
    return Manifest.create(
        file_id=bytes(16),
        version=1,
        file_name="x",
        file_size=size,
        block_size=block,
        root=tree.root,
    )


def test_q_axis_bounds_and_size():
    assert data.q_axis(0) == []
    assert data.q_axis(1) == [1]
    assert data.q_axis(10) == list(range(1, 11))
    big = data.q_axis(100_000)
    assert big[0] == 1 and big[-1] == 1024 and len(big) <= data.MAX_POINTS + 1
    assert big == sorted(set(big))


def test_detection_series_matches_core():
    n = 1000
    qs = [1, 50, 448]
    series = data.detection_series(n, qs)
    assert set(series) == set(data.EPSILONS)
    for eps, ys in series.items():
        d = damaged_blocks(n, eps)
        assert ys == [detection_probability(n, d, q) for q in qs]
    assert series[0.01][2] == pytest.approx(0.99, abs=0.01) or series[0.01][2] > 0.98
    # más daño o más q nunca baja la probabilidad
    assert all(a <= b for a, b in zip(series[0.01], series[0.25], strict=True))
    for ys in series.values():
        assert ys == sorted(ys)


def test_detection_series_tiny_file_has_at_least_one_damaged_block():
    # con n = 3, ε = 1 % da ⌈0.03⌉ = 1 bloque, no 0
    assert data.detection_series(3, [3])[0.01] == [1.0]


def test_cost_grows_with_q_and_stays_below_download_for_small_q():
    m = _manifest(4096 * 1000)
    costs = data.cost_series(m, [1, 10, 100, 1000])
    assert costs == sorted(costs) and costs[0] > 0
    assert costs[1] < m.file_size / 20  # 1 % de los bloques cuesta ~1.5 % del archivo
    assert data.cost_bytes(m, 5000) == data.cost_bytes(m, 1000)  # q se acota a n


def test_cost_of_empty_file_is_zero():
    assert data.cost_bytes(_manifest(0), 0) == 0
    assert data.cost_bytes(_manifest(0), 5) == 0


def test_repeated_miss_decreases_geometrically():
    n, eps, q = 1000, 0.01, 100
    miss = data.repeated_miss_series(n, eps, q, 5)
    p = detection_probability(n, damaged_blocks(n, eps), q)
    assert miss == pytest.approx([(1 - p) ** k for k in range(1, 6)])


def test_human_bytes():
    assert data.human_bytes(0) == "0 B"
    assert data.human_bytes(1536) == "1.5 KiB"
    assert data.human_bytes(5 * 1024 * 1024) == "5.0 MiB"
    assert data.human_bytes(3 * 1024**3) == "3.0 GiB"


def test_detections_exclude_incomplete():
    rows = [{"status": s} for s in ("PASS", "PASS", "CORRUPT", "INVALID", "INCOMPLETE")]
    assert data.detections(rows) == 2
    assert data.status_counts(rows)["PASS"] == 2
