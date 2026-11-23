"""Tasa empírica de detección frente a la probabilidad exacta.

Para cada fracción de daño ε y cada tamaño de desafío q se repiten N auditorías completas: el
servidor simulado guarda el archivo con d = ⌈ε·n⌉ bloques modificados (un bit invertido) y responde
con esos bloques y los caminos originales. Cada respuesta pasa por la misma evaluación que usa el
cliente. Se cuenta como detección toda auditoría que no termina en PASS.

Una combinación se acepta si la probabilidad exacta cae dentro del intervalo de Wilson al 99 % de
la tasa observada. Con muchas combinaciones se espera que alrededor de un 1 % quede fuera.

Uso:  uv run python experiments/run_detection.py [--n 1000] [--trials 1000] [--seed 2026]
"""

import argparse
import csv
import io
import json
import random
import time
from pathlib import Path

from merkle_audit.core.manifest import Manifest
from merkle_audit.core.merkle import tree_for_file
from merkle_audit.core.probability import (
    approx_with_replacement,
    damaged_blocks,
    detection_probability,
    wilson_interval,
)
from merkle_audit.protocol.challenge import new_challenge
from merkle_audit.protocol.messages import ProofItem
from merkle_audit.protocol.verify import Status, evaluate_response

BLOCK = 4096
EPSILONS = (0.01, 0.05, 0.10, 0.25)
Q_VALUES = (5, 10, 25, 50, 100, 200, 300)
RESULTS = Path(__file__).parent / "results"


class DamagedServer:
    """Servidor que conserva el árbol original pero tiene d bloques corruptos en disco."""

    def __init__(self, n: int, rng: random.Random):
        self.n = n
        data = rng.randbytes(n * BLOCK)
        tree, size = tree_for_file(io.BytesIO(data), BLOCK)
        self.manifest = Manifest.create(
            file_id=rng.randbytes(16),
            version=1,
            file_name="sintetico.bin",
            file_size=size,
            block_size=BLOCK,
            root=tree.root,
        )
        blocks = [data[i * BLOCK : (i + 1) * BLOCK] for i in range(n)]
        self._honest = [
            ProofItem.build(i, b, tree.proof(i)).model_dump() for i, b in enumerate(blocks)
        ]
        self._corrupt = []
        for i, b in enumerate(blocks):
            bad = bytearray(b)
            bad[rng.randrange(BLOCK)] ^= 1 << rng.randrange(8)
            self._corrupt.append(ProofItem.build(i, bytes(bad), tree.proof(i)).model_dump())
        self.damaged: set[int] = set()

    def damage(self, d: int, rng: random.Random) -> None:
        self.damaged = set(rng.sample(range(self.n), d))

    def answer(self, challenge) -> bytes:
        proofs = [
            self._corrupt[i] if i in self.damaged else self._honest[i] for i in challenge.indices
        ]
        msg = {
            "protocol": challenge.protocol,
            "type": "response",
            "audit_id": challenge.audit_id,
            "file_id": challenge.file_id,
            "version": challenge.version,
            "proofs": proofs,
        }
        return json.dumps(msg).encode()


def run(n: int, trials: int, seed: int) -> list[dict]:
    rng = random.Random(seed)  # noqa: S311  (reproducibilidad del experimento, no seguridad)
    server = DamagedServer(n, rng)
    rows = []
    for eps in EPSILONS:
        d = damaged_blocks(n, eps)
        server.damage(d, rng)
        for q in (q for q in Q_VALUES if q <= n):
            start = time.perf_counter()
            detected = 0
            for _ in range(trials):
                challenge = new_challenge(server.manifest, q, rng=rng)
                result = evaluate_response(server.manifest, challenge, server.answer(challenge))
                detected += result.status is not Status.PASS
            exact = detection_probability(n, d, q)
            lo, hi = wilson_interval(detected, trials, 0.99)
            rows.append(
                {
                    "n": n,
                    "eps": eps,
                    "d": d,
                    "q": q,
                    "trials": trials,
                    "detected": detected,
                    "empirical": round(detected / trials, 6),
                    "exact": round(exact, 6),
                    "approx_with_replacement": round(approx_with_replacement(eps, q), 6),
                    "wilson99_low": round(lo, 6),
                    "wilson99_high": round(hi, 6),
                    "within_ci": lo <= exact <= hi,
                    "seconds": round(time.perf_counter() - start, 3),
                }
            )
            r = rows[-1]
            print(
                f"ε={eps:<5} d={d:<4} q={q:<4} empírica={r['empirical']:.4f} "
                f"exacta={r['exact']:.4f} IC99=[{lo:.4f}, {hi:.4f}] "
                f"{'ok' if r['within_ci'] else 'FUERA'}"
            )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--n", type=int, default=1000, help="bloques del archivo sintético")
    parser.add_argument("--trials", type=int, default=1000, help="auditorías por combinación")
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--out", type=Path, default=RESULTS / "detection.csv")
    args = parser.parse_args()

    rows = run(args.n, args.trials, args.seed)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    outside = sum(not r["within_ci"] for r in rows)
    print(f"\n{len(rows)} combinaciones, {outside} fuera del IC 99 %. Semilla {args.seed}.")
    print(f"Resultados en {args.out}")


if __name__ == "__main__":
    main()
