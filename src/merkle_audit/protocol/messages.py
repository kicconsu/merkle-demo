"""Mensajes del protocolo de auditoría.

Todos los modelos rechazan campos desconocidos y conversiones implícitas de tipos: un mensaje que
no tiene exactamente la forma esperada no se interpreta a medias. Los hashes e identificadores van
en hex en minúsculas de longitud fija y los bloques en base64 estándar.
"""

from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints

from ..core.encoding import from_b64, from_hex, to_b64, to_hex
from ..core.params import HASH_SIZE, ID_SIZE, PROTOCOL


def _check_b64(s: str) -> str:
    from_b64(s)  # EncodingError hereda de ValueError: pydantic la reporta como error de validación
    return s


HexId = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
HexHash = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Base64 = Annotated[str, AfterValidator(_check_b64)]
Version = Annotated[int, Field(ge=1)]
Index = Annotated[int, Field(ge=0)]

ErrorCode = Literal[
    "UNKNOWN_FILE",
    "UNKNOWN_VERSION",
    "COMMITMENT_MISMATCH",
    "BAD_REQUEST",
    "VERSION_EXISTS",
    "INTERNAL",
]


class _Message(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    protocol: Literal["merkle-audit/1"] = PROTOCOL


class Challenge(_Message):
    type: Literal["challenge"] = "challenge"
    audit_id: HexId
    file_id: HexId
    version: Version
    commitment: HexHash
    indices: list[Index]


class ProofItem(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    index: Index
    block: Base64 | None  # None: el servidor declara que no tiene el bloque
    path: list[HexHash]

    @classmethod
    def build(cls, index: int, block: bytes | None, path: list[bytes]) -> "ProofItem":
        if block is None:
            return cls(index=index, block=None, path=[])
        return cls(index=index, block=to_b64(block), path=[to_hex(h) for h in path])

    def block_bytes(self) -> bytes | None:
        return None if self.block is None else from_b64(self.block)

    def path_bytes(self) -> list[bytes]:
        return [from_hex(h, HASH_SIZE) for h in self.path]


class Response(_Message):
    type: Literal["response"] = "response"
    audit_id: HexId
    file_id: HexId
    version: Version
    proofs: list[ProofItem]


class ErrorMessage(_Message):
    type: Literal["error"] = "error"
    audit_id: HexId | None
    code: ErrorCode


class UploadReceipt(_Message):
    type: Literal["upload_receipt"] = "upload_receipt"
    file_id: HexId
    version: Version
    n_blocks: Annotated[int, Field(ge=0)]
    root: HexHash
    commitment: HexHash


def id_bytes(hex_id: str) -> bytes:
    return from_hex(hex_id, ID_SIZE)
