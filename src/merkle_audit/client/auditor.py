"""Carga de archivos y auditorías: une manifiesto, desafío, transporte, evaluación y bitácora.

Una auditoría sigue el orden de la spec §8.2: validar el manifiesto (si falla, no se envía nada),
enviar el desafío, evaluar el cuerpo crudo y registrar todo en la bitácora.
"""

import json
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path

from pydantic import ValidationError

from ..core.encoding import to_hex
from ..core.manifest import Manifest, ManifestError
from ..core.merkle import MerkleTree, leaf
from ..core.params import (
    DEFAULT_BLOCK_SIZE,
    DEFAULT_TIMEOUT_S,
    PROTOCOL,
    Q_MAX,
    check_file_params,
)
from ..core.probability import damaged_blocks, detection_probability, min_challenge_size
from ..protocol.challenge import new_challenge, wire_size
from ..protocol.messages import Challenge, ErrorMessage, UploadReceipt
from ..protocol.verify import (
    AuditResult,
    Cause,
    Status,
    evaluate_response,
    incomplete,
    manifest_rejected,
)
from .auditlog import AuditLog
from .storage import ClientHome, UnknownManifest
from .transport import HttpTransport, TransportFailure, TransportTimeout

THEORY_EPS = (0.01, 0.05, 0.10, 0.25)
DEFAULT_EPS = 0.01
DEFAULT_CONFIDENCE = 0.99


class UploadError(Exception):
    """La carga falló o el recibo del servidor no coincide con el árbol del cliente."""


def package_version() -> str:
    try:
        return metadata.version("merkle-audit")
    except metadata.PackageNotFoundError:
        return "desconocida"


def now_rfc3339() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# --- Carga --------------------------------------------------------------------------------------


def upload_file(
    home: ClientHome,
    transport: HttpTransport,
    path: str | Path,
    *,
    file_id: bytes | None = None,
    block_size: int = DEFAULT_BLOCK_SIZE,
) -> Manifest:
    """Sube un archivo (§7.2) y guarda el manifiesto solo si el recibo coincide con el árbol local.

    Sin `file_id` es una carga nueva (versión 1, identificador aleatorio). Con `file_id` es una
    versión nueva de ese archivo: la última versión local + 1. El archivo no se conserva en el
    cliente más allá de esta llamada: solo queda el manifiesto.
    """
    path = Path(path)
    file_size = path.stat().st_size
    check_file_params(file_size, block_size)
    if file_id is None:
        file_id = secrets.token_bytes(16)
        version = 1
    else:
        version = (home.latest_version(file_id) or 0) + 1

    leaves: list[bytes] = []

    def chunks():
        # el árbol se calcula mientras el archivo sale hacia el servidor: una sola lectura
        with path.open("rb") as f:
            while block := f.read(block_size):
                leaves.append(leaf(len(leaves), block))
                yield block

    try:
        status, raw = transport.upload(file_id, version, block_size, file_size, chunks())
    except (TransportTimeout, TransportFailure) as e:
        raise UploadError(f"no se pudo completar la carga: {e}") from e

    receipt = _parse_receipt(status, raw)
    tree = MerkleTree(leaves)
    manifest = Manifest.create(
        file_id=file_id,
        version=version,
        file_name=path.name,
        file_size=file_size,
        block_size=block_size,
        root=tree.root,
    )
    if len(leaves) != manifest.n_blocks:
        raise UploadError("el archivo cambió mientras se subía; no se guardó el manifiesto")
    expected = (manifest.n_blocks, to_hex(manifest.root), to_hex(manifest.commitment))
    got = (receipt.n_blocks, receipt.root, receipt.commitment)
    if got != expected or (receipt.file_id, receipt.version) != (to_hex(file_id), version):
        raise UploadError(
            "el recibo del servidor no coincide con el árbol calculado localmente; "
            f"no se guardó el manifiesto (la versión {version} quedó consumida en el servidor)"
        )
    home.save_manifest(manifest)
    return manifest


def _parse_receipt(status: int, raw: bytes) -> UploadReceipt:
    try:
        data = json.loads(raw)
        if isinstance(data, dict) and data.get("type") == "error":
            code = ErrorMessage.model_validate(data).code
            raise UploadError(f"el servidor rechazó la carga: {code} (HTTP {status})")
        return UploadReceipt.model_validate(data)
    except (json.JSONDecodeError, UnicodeDecodeError, ValidationError) as e:
        raise UploadError(f"respuesta de carga inválida (HTTP {status})") from e


# --- Auditoría ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditRecord:
    audit_id: str
    file_id: str
    version: int
    result: AuditResult
    row: dict  # la fila tal como se guardó en la bitácora


def choose_q(
    manifest: Manifest,
    q: int | None = None,
    eps: float | None = None,
    confidence: float | None = None,
) -> int:
    """Tamaño del desafío: `q` explícito, o el mínimo para detectar `eps` con `confidence` (§10.2).

    Sin ninguno de los dos se usa ε = 1 % con 99 %. El resultado se acota a min(n, Q_MAX).
    """
    n = manifest.n_blocks
    if n == 0:
        return 0
    cap = min(n, Q_MAX)
    if q is not None:
        return q
    d = max(1, damaged_blocks(n, DEFAULT_EPS if eps is None else eps))
    wanted = min_challenge_size(n, d, DEFAULT_CONFIDENCE if confidence is None else confidence)
    return min(wanted, cap)


def theory_table(n: int, q: int) -> dict[str, float]:
    """P(n, d, q) para d = ⌈ε·n⌉ con ε en {1, 5, 10, 25} %."""
    if n == 0:
        return {}
    return {
        f"{round(e * 100)}%": detection_probability(n, damaged_blocks(n, e), min(q, n))
        for e in THEORY_EPS
    }


def run_audit(
    home: ClientHome,
    log: AuditLog,
    transport: HttpTransport,
    file_id: bytes,
    *,
    version: int | None = None,
    q: int | None = None,
    eps: float | None = None,
    confidence: float | None = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    origin: str = "manual",
    keep_responses: bool = False,
) -> AuditRecord:
    """Ejecuta y registra una auditoría. Lanza UnknownManifest si no hay manifiesto que usar."""
    version = home.resolve_version(file_id, version)
    started = now_rfc3339()
    base = {
        "file_id": to_hex(file_id),
        "version": version,
        "protocol": PROTOCOL,
        "package_version": package_version(),
        "timeout_s": timeout_s,
        "origin": origin,
        "started_at": started,
    }

    try:
        manifest = home.load_manifest(file_id, version)
    except ManifestError as e:
        # §5.3: el manifiesto inválido no envía desafío; queda constancia igualmente
        return _record(log, base, manifest_rejected(e), challenge=None, manifest=None)

    q_used = choose_q(manifest, q, eps, confidence)
    challenge = new_challenge(manifest, q_used)  # valida q contra n y Q_MAX
    body = json.dumps(challenge.model_dump(), separators=(",", ":")).encode()

    t0 = time.perf_counter()
    raw: bytes | None = None
    try:
        _status, raw = transport.send_challenge(body, timeout_s)
    except TransportTimeout as e:
        result = incomplete(Cause.TIMEOUT, str(e))
    except TransportFailure as e:
        result = incomplete(Cause.CONNECTION, str(e))
    else:
        if raw:
            result = None  # se evalúa abajo, midiendo aparte el tiempo de verificación
        else:
            result = incomplete(Cause.CONNECTION, "respuesta HTTP sin cuerpo")
            raw = None
    latency_ms = (time.perf_counter() - t0) * 1000

    verify_ms = None
    if result is None:
        t1 = time.perf_counter()
        result = evaluate_response(manifest, challenge, raw)
        verify_ms = (time.perf_counter() - t1) * 1000
        if keep_responses:
            home.save_response(challenge.audit_id, raw)

    return _record(
        log,
        base,
        result,
        challenge=challenge,
        manifest=manifest,
        latency_ms=latency_ms,
        challenge_bytes=wire_size(challenge),
        response_bytes=len(raw) if raw else None,
        verify_ms=verify_ms,
    )


def _record(
    log: AuditLog,
    base: dict,
    result: AuditResult,
    *,
    challenge: Challenge | None,
    manifest: Manifest | None,
    latency_ms: float | None = None,
    challenge_bytes: int | None = None,
    response_bytes: int | None = None,
    verify_ms: float | None = None,
) -> AuditRecord:
    # sin desafío (manifiesto inválido) no hubo red, pero el audit_id sigue siendo único
    audit_id = challenge.audit_id if challenge else to_hex(secrets.token_bytes(16))
    indices = challenge.indices if challenge else []
    row = {
        **base,
        "audit_id": audit_id,
        "commitment": challenge.commitment if challenge else None,
        "n": manifest.n_blocks if manifest else None,
        "q": len(indices) if challenge else None,
        "block_size": manifest.block_size if manifest else None,
        "file_size": manifest.file_size if manifest else None,
        "indices": indices,
        "status": result.status.value,
        "trivial": result.trivial,
        "findings": [
            {"index": f.index, "cause": f.cause.value, "detail": f.detail} for f in result.findings
        ],
        "server_error_code": result.server_error_code,
        "evidence": [
            {
                "index": e.index,
                "leaf": e.leaf,
                "computed_root": e.computed_root,
                "cause": e.cause.value if e.cause else None,
            }
            for e in result.evidence
        ],
        "response_sha256": result.response_sha256,
        "finished_at": now_rfc3339(),
        "latency_ms": latency_ms,
        "challenge_bytes": challenge_bytes,
        "response_bytes": response_bytes,
        "verify_ms": verify_ms,
        "theory": theory_table(manifest.n_blocks, len(indices)) if manifest else {},
    }
    log.add_audit(row)
    return AuditRecord(audit_id, base["file_id"], base["version"], result, row)


def reverify(home: ClientHome, log: AuditLog, audit_id: str) -> AuditResult:
    """Repite la verificación de una auditoría con la respuesta guardada y el mismo manifiesto."""
    row = log.get_audit(audit_id)
    if row is None:
        raise KeyError(f"no hay una auditoría {audit_id} en la bitácora")
    raw = home.load_response(audit_id)
    if raw is None:
        raise FileNotFoundError(
            "no se guardó la respuesta (la auditoría se hizo sin --keep-responses)"
        )
    if row["commitment"] is None:
        raise ValueError("esa auditoría no envió desafío (manifiesto inválido)")
    file_id = bytes.fromhex(row["file_id"])
    try:
        manifest = home.load_manifest(file_id, row["version"])
    except ManifestError as e:
        return manifest_rejected(e)
    challenge = Challenge(
        audit_id=audit_id,
        file_id=row["file_id"],
        version=row["version"],
        commitment=row["commitment"],
        indices=row["indices"],
    )
    return evaluate_response(manifest, challenge, raw)


__all__ = [
    "AuditRecord",
    "Status",
    "UnknownManifest",
    "UploadError",
    "choose_q",
    "reverify",
    "run_audit",
    "theory_table",
    "upload_file",
]
