"""Codificaciones de bytes de ancho fijo y textuales.

Los hashes e identificadores viajan en hex en minúsculas con longitud exacta, para que cada valor
tenga una sola representación. Los bloques viajan en base64 estándar con relleno, que añade un 33 %
frente al 100 % de hex.
"""

import base64
import binascii
import re


class EncodingError(ValueError):
    """Un valor textual no es una codificación válida de los bytes esperados."""


_HEX_RE = re.compile(r"[0-9a-f]*")
_U64_MAX = 2**64 - 1


def u64(x: int) -> bytes:
    """Entero sin signo en 8 bytes big-endian."""
    if not 0 <= x <= _U64_MAX:
        raise ValueError(f"{x} no cabe en u64")
    return x.to_bytes(8, "big")


def to_hex(b: bytes) -> str:
    return b.hex()


def from_hex(s: str, size: int) -> bytes:
    """Decodifica hex en minúsculas de exactamente `size` bytes; rechaza cualquier otra forma."""
    if not isinstance(s, str) or len(s) != 2 * size or not _HEX_RE.fullmatch(s):
        raise EncodingError(f"se esperaba hex en minúsculas de {2 * size} caracteres")
    return bytes.fromhex(s)


def to_b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def from_b64(s: str) -> bytes:
    """Decodifica base64 estándar con relleno; rechaza caracteres fuera del alfabeto."""
    if not isinstance(s, str):
        raise EncodingError("se esperaba una cadena base64")
    try:
        return base64.b64decode(s.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as e:
        raise EncodingError("base64 inválido") from e
