"""Costo de construir el árbol, tamaño de la prueba, tiempo de verificación y ancho de banda.

Para cada tamaño de archivo y de bloque se construye el árbol, se elige el q mínimo que detecta un
1 % de bloques dañados con 99 % de probabilidad y se mide una auditoría honesta completa: bytes del
desafío y de la respuesta y tiempo de evaluación. El ancho de banda se compara con descargar el
archivo entero. Cada medición de tiempo es la mediana de varias repeticiones.

Uso:  uv run python experiments/run_costs.py [--sizes-mib 1 10 100] [--reps 5] [--seed 2026]
"""

import argparse
import csv
import io
import json
import random
import statistics
import time
from pathlib import Path

from merkle_audit.core.manifest import Manifest
from merkle_audit.core.merkle import path_shape, tree_for_file
from merkle_audit.core.params import BLOCK_SIZES, Q_MAX
from merkle_audit.core.probability import damaged_blocks, min_challenge_size
from merkle_audit.protocol.challenge import new_challenge, wire_size
from merkle_audit.protocol.messages import ProofItem, Response
from merkle_audit.protocol.verify import Status, evaluate_response

MIB = 1024 * 1024
RESULTS = Path(__file__).parent / "results"


def _median_time(fn, reps: int) -> tuple[float, object]:
    times, out = [], None
    for _ in range(reps):
        start = time.perf_counter()
        out = fn()
        times.append(time.perf_counter() - start)
    return statistics.median(times), out


def measure(size: int, block: int, reps: int, rng: random.Random) -> dict:
    data = rng.randbytes(size)
    build_s, (tree, _) = _median_time(lambda: tree_for_file(io.BytesIO(data), block), reps)
    manifest = Manifest.create(
        file_id=rng.randbytes(16),
        version=1,
        file_name="sintetico.bin",
        file_size=size,
        block_size=block,
        root=tree.root,
    )
    n = tree.n
    q = min(min_challenge_size(n, damaged_blocks(n, 0.01), 0.99), Q_MAX)
    challenge = new_challenge(manifest, q, rng=rng)
    response = Response(
        audit_id=challenge.audit_id,
        file_id=challenge.file_id,
        version=challenge.version,
        proofs=[
            ProofItem.build(i, data[i * block : (i + 1) * block], tree.proof(i))
            for i in challenge.indices
        ],
    )
    raw = json.dumps(response.model_dump(), separators=(",", ":")).encode()
    verify_s, result = _median_time(lambda: evaluate_response(manifest, challenge, raw), reps)
    if result.status is not Status.PASS:
        raise RuntimeError("una auditoría honesta no pasó")

    path_len = statistics.mean(len(path_shape(i, n)) for i in challenge.indices)
    audit_bytes = wire_size(challenge) + len(raw)
    return {
        "file_mib": size / MIB,
        "block_size": block,
        "n": n,
        "tree_levels": len(tree.levels),
        "build_ms": round(build_s * 1000, 2),
        "q": q,
        "avg_path_hashes": round(path_len, 2),
        "proof_bytes_per_block": round(32 * path_len, 1),
        "challenge_bytes": wire_size(challenge),
        "response_bytes": len(raw),
        "audit_bytes": audit_bytes,
        "full_download_bytes": size,
        "bandwidth_ratio": round(audit_bytes / size, 4),
        "verify_ms": round(verify_s * 1000, 2),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--sizes-mib", type=float, nargs="+", default=[1, 10, 100])
    parser.add_argument("--blocks", type=int, nargs="+", default=[4096, 16384, 65536])
    parser.add_argument("--reps", type=int, default=5)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--out", type=Path, default=RESULTS / "costs.csv")
    args = parser.parse_args()
    if any(b not in BLOCK_SIZES for b in args.blocks):
        parser.error(f"los tamaños de bloque deben estar en {BLOCK_SIZES}")

    rng = random.Random(args.seed)  # noqa: S311  (datos sintéticos reproducibles)
    rows = []
    for mib in args.sizes_mib:
        for block in args.blocks:
            r = measure(int(mib * MIB), block, args.reps, rng)
            rows.append(r)
            print(
                f"{mib:>6} MiB  B={block:<6} n={r['n']:<7} árbol={r['build_ms']:>9} ms  "
                f"q={r['q']:<4} respuesta={r['response_bytes'] / MIB:7.2f} MiB "
                f"({r['bandwidth_ratio']:.2%} del archivo)  verificación={r['verify_ms']} ms"
            )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nResultados en {args.out}. Semilla {args.seed}.")


if __name__ == "__main__":
    main()
