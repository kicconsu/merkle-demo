"""Transporte HTTP (httpx) hacia el servidor. No interpreta mensajes: entrega bytes crudos.

Quien audita necesita el cuerpo exacto de la respuesta (para evaluarlo y para su huella SHA-256),
así que aquí solo se distingue "llegó un cuerpo" de "no llegó": timeout y fallos de red se
convierten en excepciones propias que el auditor traduce a INCOMPLETE.
"""

import os
from collections.abc import Iterator

import httpx

from ..core.encoding import to_hex
from ..core.params import DEFAULT_TIMEOUT_S

SERVER_ENV = "MERKLE_AUDIT_SERVER"
DEFAULT_SERVER = "http://127.0.0.1:8000"
UPLOAD_TIMEOUT_S = 600.0


class TransportTimeout(Exception):
    pass


class TransportFailure(Exception):
    pass


class HttpTransport:
    def __init__(self, base_url: str | None = None, client: httpx.Client | None = None):
        # `client` permite inyectar uno ya configurado (tests con TestClient o MockTransport)
        self.client = client or httpx.Client(
            base_url=base_url or os.environ.get(SERVER_ENV) or DEFAULT_SERVER
        )

    def close(self) -> None:
        self.client.close()

    def send_challenge(
        self, body: bytes, timeout_s: float = DEFAULT_TIMEOUT_S
    ) -> tuple[int, bytes]:
        """POST /audit. Devuelve (código HTTP, cuerpo crudo)."""
        return self._request(
            "POST",
            "/audit",
            content=body,
            headers={"Content-Type": "application/json"},
            timeout=timeout_s,
        )

    def upload(
        self,
        file_id: bytes,
        version: int,
        block_size: int,
        file_size: int,
        chunks: Iterator[bytes],
    ) -> tuple[int, bytes]:
        """PUT del archivo crudo en streaming. Devuelve (código HTTP, cuerpo crudo)."""
        return self._request(
            "PUT",
            f"/files/{to_hex(file_id)}/versions/{version}",
            params={"block_size": block_size, "file_size": file_size},
            content=chunks,
            headers={
                "Content-Type": "application/octet-stream",
                "Content-Length": str(file_size),
            },
            timeout=UPLOAD_TIMEOUT_S,
        )

    def _request(self, method: str, url: str, *, timeout: float, **kw) -> tuple[int, bytes]:
        try:
            r = self.client.request(method, url, timeout=timeout, **kw)
        except httpx.TimeoutException as e:
            raise TransportTimeout(str(e)) from e
        except httpx.HTTPError as e:
            raise TransportFailure(f"{type(e).__name__}: {e}") from e
        return r.status_code, r.content
