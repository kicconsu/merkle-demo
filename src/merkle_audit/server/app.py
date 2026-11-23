"""API HTTP del servidor: carga de versiones y respuesta a auditorías.

Toda respuesta lleva un cuerpo JSON del protocolo, incluso los errores. El trabajo con la base
(síncrono) corre en un hilo aparte para no bloquear el bucle de eventos.

Arranque: `uvicorn merkle_audit.server.app:app` (o `make server`). El directorio de datos sale de
`$MERKLE_AUDIT_SERVER_HOME`.
"""

import re
import tempfile
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from ..core.encoding import to_hex
from ..core.params import Q_MAX
from ..protocol.messages import UploadReceipt, id_bytes
from .audit import Reply, answer, error
from .store import SizeMismatch, Store, VersionExists, VersionOutOfOrder

_HEX_ID = re.compile(r"[0-9a-f]{32}")
_UINT = re.compile(r"[0-9]{1,12}")
_SPOOL_MAX = 8 * 1024 * 1024  # cuerpos más grandes pasan de memoria a un archivo temporal


def _json(reply: Reply) -> JSONResponse:
    return JSONResponse(reply.body(), status_code=reply.status)


def _uint(value: str | None) -> int | None:
    return int(value) if value is not None and _UINT.fullmatch(value) else None


def create_app(store: Store | None = None, q_max: int = Q_MAX) -> FastAPI:
    """Crea la aplicación. Sin `store`, abre el almacén del directorio por defecto al arrancar."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if not hasattr(app.state, "store"):
            app.state.store = Store()
        yield

    app = FastAPI(title="merkle-audit server", lifespan=lifespan)
    if store is not None:
        app.state.store = store

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        # ruta o método inexistente: también se responde con un mensaje del protocolo
        return _json(error("BAD_REQUEST"))

    @app.put("/files/{file_id}/versions/{version}")
    async def upload(file_id: str, version: str, request: Request) -> JSONResponse:
        st: Store = request.app.state.store
        v = _uint(version)
        block_size = _uint(request.query_params.get("block_size"))
        file_size = _uint(request.query_params.get("file_size"))
        if not _HEX_ID.fullmatch(file_id) or None in (v, block_size, file_size):
            return _json(error("BAD_REQUEST"))
        fid = id_bytes(file_id)
        try:
            # comprobación barata antes de recibir un cuerpo que puede pesar cientos de MiB;
            # put_version la repite dentro de su transacción
            if await run_in_threadpool(st.version_info, fid, v) is not None:
                return _json(error("VERSION_EXISTS"))

            with tempfile.SpooledTemporaryFile(max_size=_SPOOL_MAX) as body:
                received = 0
                async for chunk in request.stream():
                    received += len(chunk)
                    if received > file_size:
                        return _json(error("BAD_REQUEST"))
                    body.write(chunk)
                body.seek(0)
                info = await run_in_threadpool(st.put_version, fid, v, block_size, file_size, body)
        except VersionExists:
            return _json(error("VERSION_EXISTS"))
        except (VersionOutOfOrder, SizeMismatch, ValueError):
            return _json(error("BAD_REQUEST"))
        except Exception:
            return _json(error("INTERNAL"))

        receipt = UploadReceipt(
            file_id=file_id,
            version=v,
            n_blocks=info.n_blocks,
            root=to_hex(info.root),
            commitment=to_hex(info.commitment),
        )
        return _json(Reply(201, receipt))

    @app.post("/audit")
    async def audit(request: Request) -> JSONResponse:
        try:
            raw = await request.body()
            reply = await run_in_threadpool(answer, request.app.state.store, raw, q_max)
        except Exception:
            return _json(error("INTERNAL"))
        return _json(reply)

    return app


app = create_app()
