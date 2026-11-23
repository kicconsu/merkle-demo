# Experimentos

Todos los scripts son reproducibles: reciben una semilla (`--seed`, por defecto 2026) y escriben sus resultados en `results/`. Los datos son sintéticos y se generan en memoria.

| Script | Qué mide | Salida |
|---|---|---|
| `run_detection.py` | Tasa de detección observada en N auditorías completas, para ε ∈ {1, 5, 10, 25} % y varios q, frente a la probabilidad exacta `1 − C(n−d,q)/C(n,q)` y la aproximación con reemplazo | `results/detection.csv` |
| `run_costs.py` | Tiempo de construcción del árbol, longitud de los caminos, bytes de una auditoría frente a descargar el archivo y tiempo de verificación, con el q mínimo que detecta ε = 1 % con 99 % | `results/costs.csv` |
| `plot_results.py` | Gráficas interactivas de los dos CSV | `results/detection.html`, `results/costs.html` |

```sh
uv run python experiments/run_detection.py           # ~10 min con N = 1000
uv run python experiments/run_costs.py               # ~15 s; añade --sizes-mib 500 para el máximo
uv run python experiments/plot_results.py
```

**Criterio de aceptación.** Una combinación (ε, q) es consistente con la teoría si la probabilidad exacta cae dentro del intervalo de Wilson al 99 % de la tasa observada. Con 28 combinaciones se espera que, en promedio, unas 0,3 queden fuera por azar.

**Daño simulado.** El servidor conserva el árbol original y tiene d = ⌈ε·n⌉ bloques con un bit invertido. Cada respuesta pasa por la misma evaluación que usa el cliente; cuenta como detección toda auditoría que no termina en PASS.
