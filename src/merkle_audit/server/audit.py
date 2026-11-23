"""Respuesta del servidor a un desafío, separada de HTTP para poder probarla directamente.

Un servidor honesto comprueba, en este orden: que el cuerpo sea un desafío válido, que conozca el
archivo y la versión, que su compromiso coincida con el del desafío y que los índices cumplan las
reglas. Si todo está bien, devuelve el bloque vivo y el camino guardado de cada índice. Un bloque
que ya no tiene se declara con `block: null`.

Los fallos de respuesta del inyector (`faults.py`) se aplican solo al armar la respuesta, después
de todas las comprobaciones.
"""

import json
from dataclasses import dataclass

from pydantic import BaseModel, ValidationError

from ..core.encoding import to_hex
from ..core.params import Q_MAX
from ..protocol.challenge import challenge_is_valid
from ..protocol.messages import Challenge, ErrorMessage, ProofItem, Response, id_bytes
from .faults import active_response_faults
from .store import Store

HTTP_STATUS = {
    "BAD_REQUEST": 400,
    "UNKNOWN_FILE": 404,
    "UNKNOWN_VERSION": 404,
    "VERSION_EXISTS": 409,
    "COMMITMENT_MISMATCH": 409,
    "INTERNAL": 500,
}


@dataclass(frozen=True)
class Reply:
    status: int
    message: BaseModel

    def body(self) -> dict:
        return self.message.model_dump()


def error(code: str, audit_id: str | None = None) -> Reply:
    return Reply(HTTP_STATUS[code], ErrorMessage(audit_id=audit_id, code=code))


def parse_challenge(raw: bytes) -> Challenge | None:
    try:
        return Challenge.model_validate(json.loads(raw))
    except (json.JSONDecodeError, UnicodeDecodeError, ValidationError):
        return None


def answer(store: Store, raw: bytes, q_max: int = Q_MAX) -> Reply:
    challenge = parse_challenge(raw)
    if challenge is None:
        return error("BAD_REQUEST")
    aid = challenge.audit_id
    file_id = id_bytes(challenge.file_id)

    if not store.versions(file_id) or store.is_dropped(file_id):
        return error("UNKNOWN_FILE", aid)
    info = store.version_info(file_id, challenge.version)
    if info is None or info.dropped:
        return error("UNKNOWN_VERSION", aid)
    if challenge.commitment != to_hex(info.commitment):
        return error("COMMITMENT_MISMATCH", aid)
    if not challenge_is_valid(challenge, info.n_blocks, q_max):
        return error("BAD_REQUEST", aid)

    # Hasta aquí, el servidor se comporta de forma honesta. Lo que sigue consulta los fallos de
    # respuesta que haya dejado activos el inyector (camino cruzado, rollback).
    faults = active_response_faults(store, file_id, info.version)
    data_version = faults.rollback_to or info.version
    reply_version = data_version if faults.declare else challenge.version
    cross = faults.cross_paths or {}

    blocks = store.blocks(file_id, data_version, challenge.indices)
    tree = store.tree(file_id, data_version)
    proofs = []
    for i in challenge.indices:
        x = blocks.get(i)  # None si se borró o si no existe en la versión servida
        j = cross.get(i, i)
        path = tree.path(j if j < tree.n else i) if x is not None else []
        proofs.append(ProofItem.build(i, x, path))
    response = Response(
        audit_id=aid, file_id=challenge.file_id, version=reply_version, proofs=proofs
    )
    return Reply(200, response)
