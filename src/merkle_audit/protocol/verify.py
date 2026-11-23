"""Evaluación de la respuesta del servidor y estados de una auditoría.

Orden de evaluación:
  1. La respuesta debe ser un mensaje válido y estar ligada al desafío en curso (audit_id,
     file_id, versión y exactamente los índices pedidos, en el mismo orden). Si no lo está, la
     auditoría es INVALID y no se verifica ninguna prueba: no hay nada que comparar.
  2. Se verifican todas las pruebas, sin detenerse en la primera que falla, para que el reporte
     muestre cada índice dañado. Si alguna falla, la auditoría es CORRUPT.

INCOMPLETE (timeout o error de red) no aporta evidencia en ningún sentido y se reporta aparte.
"""

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum

from pydantic import ValidationError

from ..core.encoding import to_hex
from ..core.manifest import Manifest, ManifestError
from ..core.merkle import (
    ProofFailure,
    block_length,
    leaf,
    path_shape,
    root_from_path,
    verify_block,
)
from .messages import Challenge, ErrorMessage, Response


class Status(StrEnum):
    PASS = "PASS"  # noqa: S105  (estado de auditoría, no una contraseña)
    CORRUPT = "CORRUPT"
    INVALID = "INVALID"
    INCOMPLETE = "INCOMPLETE"


class Cause(StrEnum):
    MANIFEST_FORMAT = "MANIFEST_FORMAT"
    MANIFEST_MAC = "MANIFEST_MAC"
    MANIFEST_COMMITMENT = "MANIFEST_COMMITMENT"
    MALFORMED = "MALFORMED"
    AUDIT_ID_MISMATCH = "AUDIT_ID_MISMATCH"
    FILE_ID_MISMATCH = "FILE_ID_MISMATCH"
    VERSION_MISMATCH = "VERSION_MISMATCH"
    INDEX_SET_MISMATCH = "INDEX_SET_MISMATCH"
    SERVER_ERROR = "SERVER_ERROR"
    FILE_MISSING = "FILE_MISSING"
    BLOCK_MISSING = "BLOCK_MISSING"
    BLOCK_LENGTH = "BLOCK_LENGTH"
    PATH_LENGTH = "PATH_LENGTH"
    ROOT_MISMATCH = "ROOT_MISMATCH"
    TIMEOUT = "TIMEOUT"
    CONNECTION = "CONNECTION"


@dataclass(frozen=True)
class Finding:
    cause: Cause
    index: int | None = None  # None cuando la causa afecta a toda la respuesta
    detail: str = ""


@dataclass(frozen=True)
class BlockEvidence:
    """Lo que se recalculó para un índice: suficiente para explicar el resultado sin el bloque."""

    index: int
    leaf: str | None  # hex; None si el servidor no entregó el bloque
    computed_root: str | None  # hex; None si la forma de la prueba ya era inválida
    cause: Cause | None


@dataclass(frozen=True)
class AuditResult:
    status: Status
    findings: list[Finding] = field(default_factory=list)
    evidence: list[BlockEvidence] = field(default_factory=list)
    trivial: bool = False  # PASS de un archivo vacío: no hay bloques que muestrear
    server_error_code: str | None = None
    response_sha256: str | None = None


def _invalid(cause: Cause, detail: str = "", **kw) -> AuditResult:
    return AuditResult(Status.INVALID, [Finding(cause, detail=detail)], **kw)


def manifest_rejected(error: ManifestError) -> AuditResult:
    """Resultado de una auditoría que no se envió porque el manifiesto no validó."""
    return _invalid(Cause(error.failure.value), error.detail)


def incomplete(cause: Cause, detail: str = "") -> AuditResult:
    if cause not in (Cause.TIMEOUT, Cause.CONNECTION):
        raise ValueError("INCOMPLETE solo admite TIMEOUT o CONNECTION")
    return AuditResult(Status.INCOMPLETE, [Finding(cause, detail=detail)])


def parse_server_message(raw: bytes) -> Response | ErrorMessage:
    """Interpreta el cuerpo de la respuesta. Lanza ValueError si no es un mensaje válido."""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValueError("el cuerpo no es JSON") from e
    kind = data.get("type") if isinstance(data, dict) else None
    model = {"response": Response, "error": ErrorMessage}.get(kind)
    if model is None:
        raise ValueError(f"tipo de mensaje inesperado: {kind!r}")
    try:
        return model.model_validate(data)
    except ValidationError as e:
        raise ValueError(f"{e.error_count()} errores de validación") from e


def evaluate_response(manifest: Manifest, challenge: Challenge, raw: bytes) -> AuditResult:
    """Clasifica la respuesta cruda del servidor a `challenge` contra el manifiesto ya validado."""
    digest = hashlib.sha256(raw).hexdigest()
    try:
        msg = parse_server_message(raw)
    except ValueError as e:
        return _invalid(Cause.MALFORMED, str(e), response_sha256=digest)

    if isinstance(msg, ErrorMessage):
        if msg.audit_id is not None and msg.audit_id != challenge.audit_id:
            return _invalid(Cause.AUDIT_ID_MISMATCH, response_sha256=digest)
        if msg.code in ("UNKNOWN_FILE", "UNKNOWN_VERSION"):
            # el servidor admite que ya no tiene el archivo o esa versión: es una pérdida
            return AuditResult(
                Status.CORRUPT,
                [Finding(Cause.FILE_MISSING, detail=msg.code)],
                server_error_code=msg.code,
                response_sha256=digest,
            )
        return _invalid(
            Cause.SERVER_ERROR, msg.code, server_error_code=msg.code, response_sha256=digest
        )

    if msg.audit_id != challenge.audit_id:
        return _invalid(Cause.AUDIT_ID_MISMATCH, response_sha256=digest)
    if msg.file_id != challenge.file_id:
        return _invalid(Cause.FILE_ID_MISMATCH, response_sha256=digest)
    if msg.version != challenge.version:
        return _invalid(
            Cause.VERSION_MISMATCH,
            f"se pidió la versión {challenge.version} y llegó la {msg.version}",
            response_sha256=digest,
        )
    if [p.index for p in msg.proofs] != challenge.indices:
        return _invalid(Cause.INDEX_SET_MISMATCH, response_sha256=digest)

    findings, evidence = [], []
    for proof in msg.proofs:
        ev = _check_proof(manifest, proof.index, proof.block_bytes(), proof.path_bytes())
        evidence.append(ev)
        if ev.cause is not None:
            findings.append(Finding(ev.cause, proof.index))

    return AuditResult(
        Status.CORRUPT if findings else Status.PASS,
        findings,
        evidence,
        trivial=manifest.n_blocks == 0,
        response_sha256=digest,
    )


def _check_proof(
    manifest: Manifest, i: int, block: bytes | None, path: list[bytes]
) -> BlockEvidence:
    if block is None:
        return BlockEvidence(i, None, None, Cause.BLOCK_MISSING)
    failure = verify_block(
        i,
        block,
        path,
        n=manifest.n_blocks,
        block_size=manifest.block_size,
        file_size=manifest.file_size,
        root=manifest.root,
    )
    computed = None
    if failure in (None, ProofFailure.ROOT_MISMATCH):
        computed = to_hex(root_from_path(i, block, path, manifest.n_blocks))
    cause = None if failure is None else Cause(failure.value)
    return BlockEvidence(i, to_hex(leaf(i, block)), computed, cause)


def estimate_response_bytes(manifest: Manifest, indices: list[int]) -> int:
    """Tamaño aproximado de una respuesta honesta, para comparar con descargar el archivo."""
    total = 200  # cabecera JSON: protocolo, tipo, ids y versión
    for i in indices:
        length = block_length(i, manifest.n_blocks, manifest.block_size, manifest.file_size)
        total += 4 * -(-length // 3) + 67 * len(path_shape(i, manifest.n_blocks)) + 40
    return total
