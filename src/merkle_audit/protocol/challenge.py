"""Generación y validación de desafíos.

Los índices se eligen con el generador criptográfico del sistema, uniformes y sin repetición, para
que el servidor no pueda anticipar qué bloques se van a consultar. Cada auditoría lleva un
audit_id aleatorio de 128 bits, así una respuesta de una auditoría anterior no sirve para otra.
"""

import json
import random
import secrets

from ..core.encoding import to_hex
from ..core.manifest import Manifest
from ..core.params import ID_SIZE, Q_MAX, check_challenge_size
from .messages import Challenge

_SYSTEM_RNG = secrets.SystemRandom()


def new_challenge(
    manifest: Manifest, q: int, *, q_max: int = Q_MAX, rng: random.Random | None = None
) -> Challenge:
    """Desafío fresco de q índices para la versión del archivo descrita por el manifiesto.

    `rng` solo existe para que los experimentos sean reproducibles con una semilla; el cliente y
    la interfaz siempre usan el generador del sistema.
    """
    check_challenge_size(q, manifest.n_blocks, q_max)
    sampler = rng or _SYSTEM_RNG
    return Challenge(
        audit_id=to_hex(secrets.token_bytes(ID_SIZE)),
        file_id=to_hex(manifest.file_id),
        version=manifest.version,
        commitment=to_hex(manifest.commitment),
        indices=sorted(sampler.sample(range(manifest.n_blocks), q)),
    )


def challenge_is_valid(challenge: Challenge, n: int, q_max: int = Q_MAX) -> bool:
    """Lo que el servidor comprueba antes de responder: tamaño, rango, orden y sin repetidos."""
    idx = challenge.indices
    try:
        check_challenge_size(len(idx), n, q_max)
    except ValueError:
        return False
    in_range = all(0 <= i < n for i in idx)
    strictly_increasing = all(a < b for a, b in zip(idx, idx[1:], strict=False))
    return in_range and strictly_increasing


def wire_size(message: Challenge) -> int:
    """Bytes del mensaje serializado como JSON compacto, para medir ancho de banda."""
    return len(json.dumps(message.model_dump(), separators=(",", ":")).encode())
