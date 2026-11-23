"""Probabilidad de detección del muestreo sin reemplazo y herramientas para los experimentos.

Si d de los n bloques están dañados y se consultan q índices distintos elegidos uniformemente,
la auditoría no ve ningún bloque dañado con probabilidad C(n−d, q) / C(n, q), y detecta el daño con

    P(n, d, q) = 1 − C(n−d, q) / C(n, q) = 1 − Π_{j=0}^{q−1} (n−d−j) / (n−j).

Es exacta siempre que el servidor fije qué bloques pierde antes de ver el desafío, lo que se cumple
porque no puede predecir los índices. La expresión 1 − (1−ε)^q corresponde al muestreo con
reemplazo y solo aproxima este valor.
"""

import math
from fractions import Fraction
from statistics import NormalDist


def _check(n: int, d: int, q: int) -> None:
    if not (0 <= d <= n and 0 <= q <= n):
        raise ValueError(f"se requiere 0 ≤ d ≤ n y 0 ≤ q ≤ n (n={n}, d={d}, q={q})")


def detection_probability(n: int, d: int, q: int) -> float:
    """P(n, d, q) en coma flotante, por la forma de producto (estable para n grandes)."""
    _check(n, d, q)
    if d == 0 or q == 0:
        return 0.0
    if q > n - d:
        return 1.0  # es imposible elegir q índices sin tocar un bloque dañado
    miss = 1.0
    for j in range(q):
        miss *= (n - d - j) / (n - j)
    return 1.0 - miss


def detection_probability_exact(n: int, d: int, q: int) -> Fraction:
    """P(n, d, q) como fracción exacta, con coeficientes binomiales."""
    _check(n, d, q)
    return 1 - Fraction(math.comb(n - d, q), math.comb(n, q))


def approx_with_replacement(eps: float, q: int) -> float:
    """1 − (1−ε)^q: la aproximación con reemplazo, solo como referencia de comparación."""
    return 1.0 - (1.0 - eps) ** q


def damaged_blocks(n: int, eps: float) -> int:
    """d = ⌈ε·n⌉. Se redondea antes del techo para que 0.07·100 dé 7 y no 8."""
    if not 0 <= eps <= 1:
        raise ValueError("eps debe estar en [0, 1]")
    return math.ceil(round(eps * n, 9))


def min_challenge_size(n: int, d: int, confidence: float) -> int:
    """Menor q con P(n, d, q) ≥ confidence. P crece con q, así que se busca por bisección."""
    if not 1 <= d <= n:
        raise ValueError("se requiere 1 ≤ d ≤ n: sin bloques dañados no hay nada que detectar")
    if not 0 < confidence < 1:
        raise ValueError("confidence debe estar en (0, 1)")
    lo, hi = 1, n - d + 1  # con q = n − d + 1 la detección es segura
    while lo < hi:
        mid = (lo + hi) // 2
        if detection_probability(n, d, mid) >= confidence:
            hi = mid
        else:
            lo = mid + 1
    return lo


def miss_probability_repeated(n: int, d: int, q: int, k: int) -> float:
    """Probabilidad de que k auditorías independientes no detecten un daño que no cambia."""
    if k < 0:
        raise ValueError("k no puede ser negativo")
    return (1.0 - detection_probability(n, d, q)) ** k


def wilson_interval(successes: int, trials: int, confidence: float = 0.99) -> tuple[float, float]:
    """Intervalo de Wilson para una proporción binomial.

    Se usa en vez de una tolerancia fija: con N = 1000 repeticiones y P ≈ 0.64, una tolerancia
    de ±1.5 % es apenas una desviación estándar y fallaría cerca de un tercio de las veces.
    """
    if trials <= 0 or not 0 <= successes <= trials:
        raise ValueError("se requiere trials > 0 y 0 ≤ successes ≤ trials")
    z = NormalDist().inv_cdf(0.5 + confidence / 2)
    p = successes / trials
    denom = 1 + z * z / trials
    center = (p + z * z / (2 * trials)) / denom
    half = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denom
    # en los extremos el límite es exacto; la coma flotante daría 0.999… y excluiría P = 1
    lo = 0.0 if successes == 0 else max(0.0, center - half)
    hi = 1.0 if successes == trials else min(1.0, center + half)
    return lo, hi
