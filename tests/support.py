"""Archivo de prueba, su manifiesto, un servidor honesto en memoria y un servidor real para tests.

Los tests de cada ataque parten de una respuesta honesta y la alteran como lo haría un servidor
malicioso.
"""

import io
import json

from fastapi.testclient import TestClient

from merkle_audit.core.encoding import to_hex
from merkle_audit.core.manifest import Manifest
from merkle_audit.core.merkle import tree_for_file
from merkle_audit.core.params import Q_MAX
from merkle_audit.protocol.challenge import new_challenge
from merkle_audit.protocol.messages import Challenge, ProofItem, Response, UploadReceipt
from merkle_audit.protocol.verify import evaluate_response
from merkle_audit.server.app import create_app
from merkle_audit.server.store import Store

BLOCK = 4096
DATA_20 = bytes(k % 253 for k in range(19 * BLOCK + 1234))  # 20 bloques, el último corto


class HonestStore:
    def __init__(self, data: bytes, version: int = 1, file_id: bytes = bytes(range(16))):
        self.data = data
        self.tree, size = tree_for_file(io.BytesIO(data), BLOCK)
        self.manifest = Manifest.create(
            file_id=file_id,
            version=version,
            file_name="prueba.bin",
            file_size=size,
            block_size=BLOCK,
            root=self.tree.root,
        )

    def block(self, i: int) -> bytes:
        return self.data[i * BLOCK : (i + 1) * BLOCK]

    def proof_item(self, i: int) -> ProofItem:
        return ProofItem.build(i, self.block(i), self.tree.proof(i))

    def answer(self, challenge) -> dict:
        resp = Response(
            audit_id=challenge.audit_id,
            file_id=challenge.file_id,
            version=challenge.version,
            proofs=[self.proof_item(i) for i in challenge.indices],
        )
        return resp.model_dump()


def to_raw(message: dict) -> bytes:
    return json.dumps(message).encode()


class ServerHarness:
    """Servidor real (FastAPI + SQLite en un directorio temporal) y un cliente mínimo de prueba.

    El cliente hace lo que exige el protocolo: comprueba el recibo de la carga contra su propio
    árbol, crea el manifiesto y evalúa cada respuesta con `evaluate_response`.
    """

    def __init__(self, home, q_max: int = Q_MAX):
        self.store = Store(home)
        self.http = TestClient(create_app(self.store, q_max=q_max))

    def put(self, file_id: bytes, version: int, data: bytes, block_size: int = BLOCK, **params):
        query = {"block_size": block_size, "file_size": len(data), **params}
        return self.http.put(
            f"/files/{to_hex(file_id)}/versions/{version}", params=query, content=data
        )

    def upload(
        self,
        data: bytes,
        version: int = 1,
        file_id: bytes = bytes(range(16)),
        block_size: int = BLOCK,
    ) -> Manifest:
        r = self.put(file_id, version, data, block_size)
        assert r.status_code == 201, r.text
        receipt = UploadReceipt.model_validate(r.json())
        tree, size = tree_for_file(io.BytesIO(data), block_size)
        manifest = Manifest.create(
            file_id=file_id,
            version=version,
            file_name="prueba.bin",
            file_size=size,
            block_size=block_size,
            root=tree.root,
        )
        assert (receipt.n_blocks, receipt.root, receipt.commitment) == (
            manifest.n_blocks,
            to_hex(manifest.root),
            to_hex(manifest.commitment),
        )
        return manifest

    def send(self, message: dict | bytes):
        if isinstance(message, dict):
            return self.http.post("/audit", json=message)
        return self.http.post("/audit", content=message)

    def audit(self, manifest: Manifest, q: int | None = None, indices: list[int] | None = None):
        """Audita con q índices al azar (por defecto todos) o con los índices dados."""
        if indices is None:
            q = manifest.n_blocks if q is None else q
            challenge = new_challenge(manifest, min(q, Q_MAX))
        else:
            challenge = Challenge(
                audit_id=to_hex(bytes(16)),
                file_id=to_hex(manifest.file_id),
                version=manifest.version,
                commitment=to_hex(manifest.commitment),
                indices=indices,
            )
        r = self.send(challenge.model_dump())
        return r, evaluate_response(manifest, challenge, r.content)


def findings(result) -> list[tuple]:
    """Pares (índice, causa) de un resultado, para comparar de un vistazo."""
    return [(f.index, f.cause) for f in result.findings]
