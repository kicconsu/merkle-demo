"""Parámetros y límites del sistema, definidos en un único lugar."""

PROTOCOL = "merkle-audit/1"

HASH_SIZE = 32  # bytes de salida de SHA-256
ID_SIZE = 16  # bytes de file_id y audit_id
KEY_SIZE = 32  # bytes de la clave HMAC del manifiesto

BLOCK_SIZES = (4096, 8192, 16384, 32768, 65536)
DEFAULT_BLOCK_SIZE = 4096
MAX_FILE_SIZE = 500 * 1024 * 1024

Q_MAX = 1024  # índices por auditoría, acota el tamaño de una respuesta
DEFAULT_TIMEOUT_S = 60.0


def n_blocks(file_size: int, block_size: int) -> int:
    """Número de bloques de un archivo: ⌈file_size / block_size⌉ (0 para un archivo vacío)."""
    if block_size <= 0:
        raise ValueError("block_size debe ser positivo")
    if file_size < 0:
        raise ValueError("file_size no puede ser negativo")
    return -(-file_size // block_size)


def check_file_params(file_size: int, block_size: int) -> None:
    """Lanza ValueError si el tamaño de bloque o de archivo está fuera de lo permitido."""
    if block_size not in BLOCK_SIZES:
        raise ValueError(f"block_size {block_size} no permitido; opciones: {BLOCK_SIZES}")
    if not 0 <= file_size <= MAX_FILE_SIZE:
        raise ValueError(f"file_size {file_size} fuera de [0, {MAX_FILE_SIZE}]")


def check_challenge_size(q: int, n: int, q_max: int = Q_MAX) -> None:
    """Lanza ValueError si q no es un tamaño de desafío válido para un archivo de n bloques."""
    if n == 0:
        if q != 0:
            raise ValueError("un archivo vacío solo admite q = 0")
        return
    if not 1 <= q <= min(n, q_max):
        raise ValueError(f"q = {q} fuera de [1, {min(n, q_max)}]")
