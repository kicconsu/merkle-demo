"""Gráficas interactivas (HTML) a partir de los CSV de results/.

Uso:  uv run python experiments/plot_results.py
"""

import csv
from pathlib import Path

from plotly.subplots import make_subplots

RESULTS = Path(__file__).parent / "results"


def _read(name: str) -> list[dict]:
    with (RESULTS / name).open() as f:
        return list(csv.DictReader(f))


def detection() -> None:
    rows = _read("detection.csv")
    epsilons = sorted({r["eps"] for r in rows}, key=float)
    fig = make_subplots(
        rows=1,
        cols=len(epsilons),
        subplot_titles=[f"ε = {float(e):.0%}" for e in epsilons],
        shared_yaxes=True,
    )
    for col, eps in enumerate(epsilons, start=1):
        sub = [r for r in rows if r["eps"] == eps]
        q = [int(r["q"]) for r in sub]
        emp = [float(r["empirical"]) for r in sub]
        first = col == 1
        fig.add_scatter(
            x=q,
            y=[float(r["exact"]) for r in sub],
            mode="lines",
            name="exacta (sin reemplazo)",
            line={"color": "#2b6cb0"},
            showlegend=first,
            row=1,
            col=col,
        )
        fig.add_scatter(
            x=q,
            y=[float(r["approx_with_replacement"]) for r in sub],
            mode="lines",
            name="aproximación 1 − (1−ε)^q",
            line={"color": "#a0aec0", "dash": "dash"},
            showlegend=first,
            row=1,
            col=col,
        )
        fig.add_scatter(
            x=q,
            y=emp,
            mode="markers",
            name="empírica (IC Wilson 99 %)",
            marker={"color": "#c05621", "size": 7},
            error_y={
                "type": "data",
                "symmetric": False,
                "array": [float(r["wilson99_high"]) - e for r, e in zip(sub, emp, strict=True)],
                "arrayminus": [e - float(r["wilson99_low"]) for r, e in zip(sub, emp, strict=True)],
            },
            showlegend=first,
            row=1,
            col=col,
        )
        fig.update_xaxes(title_text="q (bloques consultados)", type="log", row=1, col=col)
    n, trials = rows[0]["n"], rows[0]["trials"]
    fig.update_yaxes(title_text="probabilidad de detección", row=1, col=1)
    fig.update_layout(
        title=f"Detección empírica vs. teórica (n = {n}, N = {trials} auditorías por punto)",
        template="plotly_white",
        height=450,
    )
    fig.write_html(RESULTS / "detection.html", include_plotlyjs="cdn")


def costs() -> None:
    rows = _read("costs.csv")
    fig = make_subplots(
        rows=1,
        cols=2,
        subplot_titles=["Bytes de una auditoría / tamaño del archivo", "Tiempo de verificación"],
    )
    for block in sorted({r["block_size"] for r in rows}, key=int):
        sub = [r for r in rows if r["block_size"] == block]
        x = [float(r["file_mib"]) for r in sub]
        label = f"B = {int(block) // 1024} KiB"
        fig.add_scatter(
            x=x,
            y=[float(r["bandwidth_ratio"]) for r in sub],
            mode="lines+markers",
            name=label,
            legendgroup=label,
            row=1,
            col=1,
        )
        fig.add_scatter(
            x=x,
            y=[float(r["verify_ms"]) for r in sub],
            mode="lines+markers",
            name=label,
            legendgroup=label,
            showlegend=False,
            row=1,
            col=2,
        )
    fig.add_hline(y=1, line_dash="dot", annotation_text="descargar todo", row=1, col=1)
    fig.update_xaxes(title_text="tamaño del archivo (MiB)", type="log")
    fig.update_yaxes(type="log", tickformat=".0%", row=1, col=1)
    fig.update_yaxes(title_text="ms", row=1, col=2)
    fig.update_layout(
        title="Costo de una auditoría que detecta ε = 1 % con 99 %",
        template="plotly_white",
        height=450,
    )
    fig.write_html(RESULTS / "costs.html", include_plotlyjs="cdn")


if __name__ == "__main__":
    detection()
    costs()
    print(f"Gráficas en {RESULTS}")
