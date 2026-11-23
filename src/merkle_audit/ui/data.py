"""Cálculos del panel, sin Streamlit: curvas de detección y costo, y resúmenes de la bitácora.

Separado de `app.py` para poder probarlo sin interfaz. Solo usa `core` y `protocol`: la curva de
detección sale de `core.probability` (la misma fórmula que el resto del producto) y el costo, de
`protocol.verify.estimate_response_bytes`.
"""

from collections import Counter
from collections.abc import Sequence

from ..core.manifest import Manifest
from ..core.params import Q_MAX
from ..core.probability import (
    approx_with_replacement,
    damaged_blocks,
    detection_probability,
    miss_probability_repeated,
)
from ..protocol.verify import estimate_response_bytes

EPSILONS = (0.01, 0.05, 0.10, 0.25)
MAX_POINTS = 200

STATUS_COLORS = {
    "PASS": "#2a9d8f",
    "CORRUPT": "#d62828",
    "INVALID": "#e76f51",
    "INCOMPLETE": "#8d99ae",
}


def q_axis(n: int, q_max: int = Q_MAX) -> list[int]:
    """Valores de q a graficar: de 1 a min(n, q_max), con a lo sumo MAX_POINTS puntos."""
    top = min(n, q_max)
    if top < 1:
        return []
    step = max(1, -(-top // MAX_POINTS))
    qs = list(range(1, top + 1, step))
    if qs[-1] != top:
        qs.append(top)
    return qs


def detection_series(
    n: int, qs: Sequence[int], eps_values: Sequence[float] = EPSILONS
) -> dict[float, list[float]]:
    """P(n, d, q) para cada ε, con d = ⌈ε·n⌉ y d ≥ 1."""
    return {
        e: [detection_probability(n, max(1, damaged_blocks(n, e)), q) for q in qs]
        for e in eps_values
    }


def replacement_series(eps: float, qs: Sequence[int]) -> list[float]:
    """La aproximación con reemplazo 1 − (1−ε)^q, solo como referencia visual."""
    return [approx_with_replacement(eps, q) for q in qs]


def _spread(n: int, q: int) -> list[int]:
    """q índices repartidos por todo el archivo: una muestra representativa para estimar costos."""
    return sorted({(k * n) // q for k in range(q)})


def cost_bytes(manifest: Manifest, q: int) -> int:
    """Bytes aproximados de la respuesta honesta a un desafío de q bloques."""
    if manifest.n_blocks == 0 or q <= 0:
        return 0
    return estimate_response_bytes(manifest, _spread(manifest.n_blocks, min(q, manifest.n_blocks)))


def cost_series(manifest: Manifest, qs: Sequence[int]) -> list[int]:
    return [cost_bytes(manifest, q) for q in qs]


def repeated_miss_series(n: int, eps: float, q: int, max_k: int) -> list[float]:
    """Probabilidad de no detectar tras k = 1..max_k auditorías independientes con daño fijo."""
    d = max(1, damaged_blocks(n, eps))
    return [miss_probability_repeated(n, d, q, k) for k in range(1, max_k + 1)]


def human_bytes(x: float) -> str:
    for unit in ("B", "KiB", "MiB"):
        if abs(x) < 1024:
            return f"{x:.0f} {unit}" if unit == "B" else f"{x:.1f} {unit}"
        x /= 1024
    return f"{x:.1f} GiB"


def status_counts(rows: Sequence[dict]) -> Counter:
    return Counter(r["status"] for r in rows)


def detections(rows: Sequence[dict]) -> int:
    """Auditorías que cuentan como detección (§8.1): CORRUPT e INVALID. INCOMPLETE no cuenta."""
    return sum(1 for r in rows if r["status"] in ("CORRUPT", "INVALID"))


def audit_table(rows: Sequence[dict]) -> list[dict]:
    """Filas planas para mostrar en una tabla."""
    return [
        {
            "inicio": r["started_at"],
            "estado": r["status"],
            "audit_id": r["audit_id"],
            "versión": r["version"],
            "q": r["q"],
            "n": r["n"],
            "origen": r["origin"],
            "causas": ", ".join(sorted({f["cause"] for f in r["findings"]})) or "-",
            "latencia (ms)": None if r["latency_ms"] is None else round(r["latency_ms"], 1),
            "respuesta (B)": r["response_bytes"],
        }
        for r in rows
    ]
