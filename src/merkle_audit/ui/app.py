"""Panel Streamlit del auditor: carga, auditoría, probabilidad y costo, historial y programas.

Arranque: `make ui` (equivale a `streamlit run src/merkle_audit/ui/app.py`). El panel usa la misma
lógica que el CLI (`merkle_audit.client`) y los mismos cálculos de `core.probability`; no repite
nada de criptografía. Como el CLI, no expone ninguna opción para fijar la semilla de los índices.
"""

import tempfile
from pathlib import Path

import plotly.graph_objects as go
import streamlit as st

from merkle_audit.client.auditlog import AuditLog
from merkle_audit.client.auditor import (
    UploadError,
    choose_q,
    reverify,
    run_audit,
    theory_table,
    upload_file,
)
from merkle_audit.client.scheduler import add_schedule, run_due
from merkle_audit.client.storage import ClientHome, UnknownManifest
from merkle_audit.client.transport import DEFAULT_SERVER, SERVER_ENV, HttpTransport
from merkle_audit.core.encoding import to_hex
from merkle_audit.core.manifest import Manifest, ManifestError
from merkle_audit.core.params import (
    BLOCK_SIZES,
    DEFAULT_BLOCK_SIZE,
    DEFAULT_TIMEOUT_S,
    MAX_FILE_SIZE,
    Q_MAX,
)
from merkle_audit.core.probability import damaged_blocks
from merkle_audit.ui import data

AVISO_EVIDENCIA = (
    "PASS es evidencia probabilística sobre los bloques consultados: no demuestra que el archivo "
    "completo esté disponible ni que siga intacto después de esta auditoría."
)


# --- Estado compartido --------------------------------------------------------------------------


@st.cache_resource
def _transport(url: str) -> HttpTransport:
    return HttpTransport(url)


def _server_reachable(transport: HttpTransport) -> bool:
    try:
        transport.client.get("/", timeout=2.0)  # cualquier respuesta HTTP basta: hay servidor
    except Exception:
        return False
    return True


def _sidebar() -> tuple[ClientHome, AuditLog, HttpTransport]:
    import os

    st.sidebar.header("Conexión")
    home_dir = st.sidebar.text_input(
        "Directorio del cliente",
        value=os.environ.get("MERKLE_AUDIT_HOME", ".merkle-audit-client"),
    )
    url = st.sidebar.text_input("Servidor", value=os.environ.get(SERVER_ENV, DEFAULT_SERVER))
    home = ClientHome(home_dir)
    log = AuditLog(home.db_path)
    transport = _transport(url)
    if _server_reachable(transport):
        st.sidebar.success("Servidor alcanzable")
    else:
        st.sidebar.error("Sin respuesta del servidor. Arránquelo con `make server`.")
    return home, log, transport


def _select_file(home: ClientHome) -> tuple[bytes, int] | None:
    st.sidebar.header("Archivo")
    ids = home.file_ids()
    if not ids:
        st.sidebar.info("Aún no hay archivos cargados.")
        return None

    def label(fid: bytes) -> str:
        try:
            name = home.load_manifest(fid).file_name
        except (ManifestError, UnknownManifest):
            name = "manifiesto inválido"
        return f"{name} · {to_hex(fid)[:8]}"

    fid = st.sidebar.selectbox("Archivo", ids, format_func=label)
    versions = home.versions(fid)
    version = st.sidebar.selectbox("Versión", versions, index=len(versions) - 1)
    return fid, version


def _load_manifest(home: ClientHome, sel: tuple[bytes, int] | None) -> Manifest | None:
    if sel is None:
        return None
    try:
        return home.load_manifest(*sel)
    except ManifestError as e:
        st.error(f"Manifiesto inválido ({e.failure.value}): {e.detail}. No se puede auditar.")
    except UnknownManifest as e:
        st.error(str(e))
    return None


def _audit_params(manifest: Manifest | None) -> dict:
    """Controles de la barra lateral. Devuelve los argumentos de `run_audit`."""
    st.sidebar.header("Auditoría")
    mode = st.sidebar.radio("Elegir el tamaño del desafío", ["Por objetivo", "Manual (q)"])
    timeout = st.sidebar.number_input("Timeout (s)", 1.0, 3600.0, DEFAULT_TIMEOUT_S)
    params: dict = {"timeout_s": float(timeout)}
    if mode == "Manual (q)":
        top = max(1, min(manifest.n_blocks, Q_MAX)) if manifest else 1
        params["q"] = int(st.sidebar.number_input("q (bloques)", 1, top, min(top, 100)))
    else:
        eps = st.sidebar.select_slider(
            "Fracción dañada a detectar (ε)", [0.005, 0.01, 0.05, 0.10, 0.25], value=0.01
        )
        conf = st.sidebar.select_slider(
            "Probabilidad de detección", [0.90, 0.95, 0.99, 0.999], value=0.99
        )
        params |= {"eps": float(eps), "confidence": float(conf)}
    return params


# --- Pestañas -----------------------------------------------------------------------------------


def _tab_files(home, log, transport, sel, manifest) -> None:
    st.subheader("Cargar un archivo")
    up = st.file_uploader("Archivo (hasta 500 MB)", key="uploader")
    c1, c2 = st.columns(2)
    block = c1.selectbox(
        "Tamaño de bloque", BLOCK_SIZES, index=BLOCK_SIZES.index(DEFAULT_BLOCK_SIZE)
    )
    new_version = c2.checkbox(
        "Nueva versión del archivo seleccionado", value=False, disabled=sel is None
    )
    if st.button("Subir", disabled=up is None, type="primary"):
        if up.size > MAX_FILE_SIZE:
            st.error("El archivo supera los 500 MiB permitidos.")
        else:
            try:
                with tempfile.TemporaryDirectory() as tmp:
                    path = Path(tmp) / Path(up.name).name
                    path.write_bytes(up.getbuffer())
                    with st.spinner("Subiendo y calculando el árbol…"):
                        m = upload_file(
                            home,
                            transport,
                            path,
                            file_id=sel[0] if new_version and sel else None,
                            block_size=block,
                        )
                st.success(f"Cargado: versión {m.version}, {m.n_blocks} bloques.")
                st.code(f"file_id  {to_hex(m.file_id)}\nraíz     {to_hex(m.root)}")
            except (UploadError, OSError, ValueError) as e:
                st.error(str(e))

    if manifest:
        st.subheader("Manifiesto vigente")
        a, b, c = st.columns(3)
        a.metric("Bloques (n)", manifest.n_blocks)
        b.metric("Tamaño de bloque", data.human_bytes(manifest.block_size))
        c.metric("Tamaño del archivo", data.human_bytes(manifest.file_size))
        st.code(
            f"file_id     {to_hex(manifest.file_id)}\nversión     {manifest.version}\n"
            f"raíz        {to_hex(manifest.root)}\ncompromiso  {to_hex(manifest.commitment)}\n"
            f"creado      {manifest.created_at}",
            language=None,
        )


def _show_result(record) -> None:
    r = record.result
    row = record.row
    text = f"{r.status.value} · auditoría {record.audit_id}"
    if r.status.value == "PASS":
        st.success(text + (" · trivial: archivo vacío" if r.trivial else ""))
        st.caption(AVISO_EVIDENCIA)
    elif r.status.value == "INCOMPLETE":
        st.warning(text + " · sin evidencia en ningún sentido")
    else:
        st.error(text)
    if r.findings:
        st.table(
            [
                {
                    "índice": "—" if f.index is None else f.index,
                    "causa": f.cause.value,
                    "detalle": f.detail,
                }
                for f in r.findings
            ]
        )
    cols = st.columns(3)
    if row["latency_ms"] is not None:
        cols[0].metric("Latencia", f"{row['latency_ms']:.1f} ms")
        cols[1].metric("Desafío", data.human_bytes(row["challenge_bytes"] or 0))
        cols[2].metric("Respuesta", data.human_bytes(row["response_bytes"] or 0))


def _tab_audit(home, log, transport, sel, manifest, params) -> None:
    if manifest is None:
        st.info("Cargue un archivo o seleccione uno con manifiesto válido.")
        return
    q = choose_q(manifest, params.get("q"), params.get("eps"), params.get("confidence"))
    n = manifest.n_blocks
    st.subheader("Desafío")
    a, b, c = st.columns(3)
    a.metric("Bloques a consultar (q)", f"{q} de {n}")
    if n:
        a.caption(f"q ≤ {min(n, Q_MAX)} (Q_MAX = {Q_MAX})")
        b.metric("Respuesta estimada", data.human_bytes(data.cost_bytes(manifest, q)))
        c.metric("Descargar todo", data.human_bytes(manifest.file_size))
        probs = theory_table(n, q)
        st.table(
            [
                {
                    "daño ε": k,
                    "bloques dañados d": max(1, damaged_blocks(n, float(k[:-1]) / 100)),
                    "P(detección)": f"{v:.4%}",
                }
                for k, v in probs.items()
            ]
        )
    keep = st.checkbox("Guardar la respuesta (solo datos sintéticos)", value=False)
    if st.button("Auditar ahora", type="primary"):
        try:
            record = run_audit(
                home,
                log,
                transport,
                manifest.file_id,
                version=manifest.version,
                q=q,
                timeout_s=params["timeout_s"],
                keep_responses=keep,
            )
        except (UnknownManifest, ValueError) as e:
            st.error(str(e))
        else:
            st.session_state["last_audit"] = record
    if "last_audit" in st.session_state:
        _show_result(st.session_state["last_audit"])


def _tab_curves(manifest, params) -> None:
    if manifest is None or manifest.n_blocks == 0:
        st.info("Seleccione un archivo con al menos un bloque.")
        return
    n = manifest.n_blocks
    q_now = choose_q(manifest, params.get("q"), params.get("eps"), params.get("confidence"))
    qs = data.q_axis(n)

    st.subheader("Probabilidad de detección según q")
    show_repl = st.checkbox("Mostrar la aproximación con reemplazo (referencia)", value=False)
    fig = go.Figure()
    for eps, ys in data.detection_series(n, qs).items():
        fig.add_scatter(x=qs, y=ys, mode="lines", name=f"ε = {eps:.0%}")
        if show_repl:
            fig.add_scatter(
                x=qs,
                y=data.replacement_series(eps, qs),
                mode="lines",
                line={"dash": "dot"},
                name=f"1−(1−ε)^q, ε = {eps:.0%}",
            )
    fig.add_vline(x=q_now, line_dash="dash", annotation_text=f"q = {q_now}")
    fig.update_layout(
        xaxis_title="q (bloques consultados)",
        yaxis_title="P(detección)",
        yaxis={"range": [0, 1.02]},
        margin={"t": 20},
    )
    st.plotly_chart(fig, use_container_width=True)
    st.caption(
        "Muestreo sin reemplazo: P = 1 − C(n−d, q)/C(n, q), con d = ⌈ε·n⌉ bloques dañados. "
        "Es exacta si el servidor fija qué bloques pierde antes de ver el desafío."
    )

    st.subheader("Costo según q")
    costs = data.cost_series(manifest, qs)
    fig = go.Figure()
    fig.add_scatter(x=qs, y=costs, mode="lines", name="respuesta estimada")
    fig.add_hline(
        y=manifest.file_size,
        line_dash="dash",
        annotation_text=f"descargar todo ({data.human_bytes(manifest.file_size)})",
    )
    fig.add_vline(x=q_now, line_dash="dash")
    fig.update_layout(xaxis_title="q", yaxis_title="bytes", margin={"t": 20})
    st.plotly_chart(fig, use_container_width=True)
    cost_now = data.cost_bytes(manifest, q_now)
    st.caption(
        f"Con q = {q_now}: {data.human_bytes(cost_now)} frente a "
        f"{data.human_bytes(manifest.file_size)} ({cost_now / max(1, manifest.file_size):.1%}). "
        "Estimación por la fórmula de la spec §10.4."
    )

    st.subheader("Varias auditorías seguidas")
    eps = st.select_slider("ε", [0.01, 0.05, 0.10, 0.25], value=0.01, key="eps_rep")
    k_max = st.slider("Auditorías", 1, 50, 10)
    miss = data.repeated_miss_series(n, eps, q_now, k_max)
    fig = go.Figure()
    fig.add_scatter(x=list(range(1, k_max + 1)), y=miss, mode="lines+markers")
    fig.update_layout(
        xaxis_title="auditorías independientes",
        yaxis_title="P(no detectar el daño)",
        yaxis_type="log",
        margin={"t": 20},
    )
    st.plotly_chart(fig, use_container_width=True)
    st.caption(
        "Con daño estático y índices nuevos en cada auditoría, la probabilidad de no detectarlo "
        "baja como (1−P)^k. Eso no prueba disponibilidad: el daño puede ocurrir después de la "
        "última auditoría y los bloques nunca consultados no tienen garantía."
    )


def _tab_history(home, log, sel) -> None:
    only_file = st.checkbox(
        "Solo el archivo seleccionado", value=sel is not None, disabled=sel is None
    )
    rows = log.list_audits(to_hex(sel[0]) if only_file and sel else None, limit=500)
    if not rows:
        st.info("Todavía no hay auditorías registradas.")
        return
    counts = data.status_counts(rows)
    cols = st.columns(5)
    cols[0].metric("Auditorías", len(rows))
    for col, status in zip(cols[1:], data.STATUS_COLORS, strict=True):
        col.metric(status, counts.get(status, 0))

    fig = go.Figure()
    for status, color in data.STATUS_COLORS.items():
        sub = [r for r in rows if r["status"] == status]
        if sub:
            fig.add_scatter(
                x=[r["started_at"] for r in sub],
                y=[r["q"] or 0 for r in sub],
                mode="markers",
                name=status,
                marker={"color": color, "size": 10},
                text=[r["audit_id"][:8] for r in sub],
            )
    fig.update_layout(yaxis_title="q", margin={"t": 20})
    st.plotly_chart(fig, use_container_width=True)

    st.dataframe(data.audit_table(rows), use_container_width=True, hide_index=True)

    st.subheader("Detalle")
    chosen = st.selectbox("Auditoría", [r["audit_id"] for r in rows])
    row = next(r for r in rows if r["audit_id"] == chosen)
    st.json(
        {
            k: row[k]
            for k in (
                "audit_id",
                "file_id",
                "version",
                "commitment",
                "protocol",
                "package_version",
                "n",
                "q",
                "block_size",
                "file_size",
                "timeout_s",
                "origin",
                "status",
                "trivial",
                "server_error_code",
                "response_sha256",
                "started_at",
                "finished_at",
                "latency_ms",
                "challenge_bytes",
                "response_bytes",
                "verify_ms",
            )
        },
        expanded=False,
    )
    st.write("Índices consultados:", row["indices"])
    if row["findings"]:
        st.write("Hallazgos")
        st.table(row["findings"])
    with st.expander("Evidencia por índice (hoja y raíz recomputadas)"):
        st.dataframe(row["evidence"], use_container_width=True, hide_index=True)
    with st.expander("Contexto teórico"):
        st.write(row["theory"])
    if home.response_path(chosen).is_file() and st.button("Reverificar con la respuesta guardada"):
        try:
            res = reverify(home, log, chosen)
            st.write(f"Reverificación: **{res.status.value}**")
            for f in res.findings:
                st.write(f"- {f.cause.value}" + ("" if f.index is None else f" (índice {f.index})"))
        except (KeyError, FileNotFoundError, ValueError) as e:
            st.error(str(e))


def _tab_schedules(home, log, transport, sel) -> None:
    st.subheader("Programas")
    schedules = log.list_schedules()
    if schedules:
        st.dataframe(
            [
                {
                    "id": s.id,
                    "archivo": s.file_id,
                    "cada (s)": s.every_s,
                    "q": s.q,
                    "ε": s.target_eps,
                    "confianza": s.confidence,
                    "última": s.last_run_at,
                }
                for s in schedules
            ],
            hide_index=True,
            use_container_width=True,
        )
        rid = st.selectbox("Eliminar programa", [s.id for s in schedules])
        if st.button("Eliminar"):
            log.remove_schedule(rid)
            st.rerun()
        if st.button("Ejecutar ahora los vencidos"):
            records = run_due(home, log, transport)
            st.write(f"{len(records)} auditorías ejecutadas.")
            for r in records:
                st.write(f"- {r.result.status.value} · {r.audit_id} · {r.row['origin']}")
    else:
        st.info("No hay programas.")

    st.subheader("Nuevo programa")
    if sel is None:
        st.caption("Seleccione un archivo.")
        return
    every = st.text_input("Cada (30s, 10m, 2h, 1d)", "10m")
    kind = st.radio("Tamaño", ["q fijo", "Objetivo ε y confianza"], horizontal=True)
    kw: dict = {}
    if kind == "q fijo":
        kw["q"] = int(st.number_input("q", 1, Q_MAX, 100))
    else:
        kw["target_eps"] = st.select_slider(
            "ε", [0.005, 0.01, 0.05, 0.10, 0.25], value=0.01, key="s_eps"
        )
        kw["confidence"] = st.select_slider(
            "Confianza", [0.90, 0.95, 0.99, 0.999], value=0.99, key="s_conf"
        )
    if st.button("Crear programa"):
        try:
            sid = add_schedule(log, file_id=to_hex(sel[0]), every=every, **kw)
            st.success(f"Programa {sid} creado.")
            st.caption("Se ejecuta con `merkle-audit schedule run` o con el botón de arriba.")
        except ValueError as e:
            st.error(str(e))


# --- Entrada ------------------------------------------------------------------------------------


def main() -> None:
    st.set_page_config(page_title="Auditor de integridad", layout="wide")
    st.title("Auditor probabilístico de integridad")
    st.caption(
        "Árbol de Merkle con SHA-256 y desafíos aleatorios. Detecta pérdida o corrupción por "
        "muestreo; no es una prueba de que todo el archivo esté disponible."
    )
    home, log, transport = _sidebar()
    sel = _select_file(home)
    manifest = _load_manifest(home, sel)
    params = _audit_params(manifest)

    t_files, t_audit, t_curves, t_hist, t_sched = st.tabs(
        ["Archivos", "Auditar", "Probabilidad y costo", "Historial", "Programas"]
    )
    with t_files:
        _tab_files(home, log, transport, sel, manifest)
    with t_audit:
        _tab_audit(home, log, transport, sel, manifest, params)
    with t_curves:
        _tab_curves(manifest, params)
    with t_hist:
        _tab_history(home, log, sel)
    with t_sched:
        _tab_schedules(home, log, transport, sel)


main()
