"""Manifiesto local del archivo: la huella confiable contra la que se verifica cada auditoría.

El manifiesto se autentica con HMAC-SHA256 bajo una clave que solo tiene el cliente. Un manifiesto
alterado se rechaza al cargarlo, antes de enviar ningún desafío, en vez de notarse solo porque las
pruebas dejan de cuadrar.

El MAC se calcula sobre una serialización canónica (JSON con claves ordenadas, sin espacios y solo
ASCII), así que el mismo contenido produce siempre los mismos bytes.
"""

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from .encoding import EncodingError, from_hex, to_hex
from .merkle import commit
from .params import HASH_SIZE, ID_SIZE, KEY_SIZE, check_file_params, n_blocks

FORMAT = "merkle-audit/manifest"
FORMAT_VERSION = 1
_MAC_LABEL = b"merkle-audit/manifest/1\x00"

_FIELDS: dict[str, type] = {
    "format": str,
    "format_version": int,
    "file_id": str,
    "version": int,
    "file_name": str,
    "file_size": int,
    "block_size": int,
    "n_blocks": int,
    "root": str,
    "commitment": str,
    "created_at": str,
    "mac": str,
}


class ManifestFailure(StrEnum):
    MANIFEST_FORMAT = "MANIFEST_FORMAT"
    MANIFEST_MAC = "MANIFEST_MAC"
    MANIFEST_COMMITMENT = "MANIFEST_COMMITMENT"


class ManifestError(Exception):
    def __init__(self, failure: ManifestFailure, detail: str):
        super().__init__(f"{failure}: {detail}")
        self.failure = failure
        self.detail = detail


@dataclass(frozen=True)
class Manifest:
    file_id: bytes
    version: int
    file_name: str
    file_size: int
    block_size: int
    n_blocks: int
    root: bytes
    commitment: bytes
    created_at: str

    @classmethod
    def create(
        cls,
        *,
        file_id: bytes,
        version: int,
        file_name: str,
        file_size: int,
        block_size: int,
        root: bytes,
        created_at: str | None = None,
    ) -> "Manifest":
        """Construye un manifiesto nuevo calculando n y el compromiso."""
        check_file_params(file_size, block_size)
        if version < 1:
            raise ValueError("version debe ser ≥ 1")
        n = n_blocks(file_size, block_size)
        return cls(
            file_id=file_id,
            version=version,
            file_name=file_name,
            file_size=file_size,
            block_size=block_size,
            n_blocks=n,
            root=root,
            commitment=commit(file_id, version, block_size, file_size, n, root),
            created_at=created_at or _now_utc(),
        )

    def to_dict(self) -> dict[str, Any]:
        """Campos del manifiesto en su forma textual, sin el MAC."""
        return {
            "format": FORMAT,
            "format_version": FORMAT_VERSION,
            "file_id": to_hex(self.file_id),
            "version": self.version,
            "file_name": self.file_name,
            "file_size": self.file_size,
            "block_size": self.block_size,
            "n_blocks": self.n_blocks,
            "root": to_hex(self.root),
            "commitment": to_hex(self.commitment),
            "created_at": self.created_at,
        }


def _now_utc() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_key() -> bytes:
    return secrets.token_bytes(KEY_SIZE)


def canonical(fields: dict[str, Any]) -> bytes:
    """Serialización canónica de los campos, excluido el MAC."""
    body = {k: v for k, v in fields.items() if k != "mac"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def compute_mac(key: bytes, fields: dict[str, Any]) -> bytes:
    return hmac.new(key, _MAC_LABEL + canonical(fields), hashlib.sha256).digest()


def dumps(manifest: Manifest, key: bytes) -> str:
    """Manifiesto sellado con su MAC, listo para guardar en disco."""
    fields = manifest.to_dict()
    fields["mac"] = to_hex(compute_mac(key, fields))
    return json.dumps(fields, indent=2, ensure_ascii=False) + "\n"


def loads(text: str | bytes, key: bytes) -> Manifest:
    """Carga y valida un manifiesto. Lanza ManifestError con la primera causa encontrada.

    Orden: forma de los campos, MAC, coherencia de parámetros y, por último, el compromiso.
    El MAC va antes que la coherencia para que un manifiesto manipulado se reporte como tal.
    """
    fmt = ManifestFailure.MANIFEST_FORMAT
    try:
        fields = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ManifestError(fmt, "JSON inválido") from e
    if not isinstance(fields, dict) or set(fields) != set(_FIELDS):
        raise ManifestError(fmt, "campos faltantes o desconocidos")
    for name, typ in _FIELDS.items():
        value = fields[name]
        # bool es subclase de int en Python; aquí no se acepta como entero
        if not isinstance(value, typ) or isinstance(value, bool):
            raise ManifestError(fmt, f"el campo {name} debe ser {typ.__name__}")
    if fields["format"] != FORMAT or fields["format_version"] != FORMAT_VERSION:
        raise ManifestError(fmt, "formato o versión de formato desconocidos")
    try:
        file_id = from_hex(fields["file_id"], ID_SIZE)
        root = from_hex(fields["root"], HASH_SIZE)
        commitment = from_hex(fields["commitment"], HASH_SIZE)
        mac = from_hex(fields["mac"], HASH_SIZE)
    except EncodingError as e:
        raise ManifestError(fmt, str(e)) from e

    if not hmac.compare_digest(mac, compute_mac(key, fields)):
        raise ManifestError(ManifestFailure.MANIFEST_MAC, "el MAC no verifica")

    try:
        check_file_params(fields["file_size"], fields["block_size"])
    except ValueError as e:
        raise ManifestError(fmt, str(e)) from e
    if fields["version"] < 1:
        raise ManifestError(fmt, "version debe ser ≥ 1")
    if fields["n_blocks"] != n_blocks(fields["file_size"], fields["block_size"]):
        raise ManifestError(fmt, "n_blocks no corresponde a file_size y block_size")

    manifest = Manifest(
        file_id=file_id,
        version=fields["version"],
        file_name=fields["file_name"],
        file_size=fields["file_size"],
        block_size=fields["block_size"],
        n_blocks=fields["n_blocks"],
        root=root,
        commitment=commitment,
        created_at=fields["created_at"],
    )
    expected = commit(
        file_id, manifest.version, manifest.block_size, manifest.file_size, manifest.n_blocks, root
    )
    if not hmac.compare_digest(commitment, expected):
        raise ManifestError(ManifestFailure.MANIFEST_COMMITMENT, "el compromiso no corresponde")
    return manifest
