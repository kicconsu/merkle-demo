"""Directorio de datos del cliente: clave HMAC, manifiestos y respuestas guardadas.

Disposición bajo `$MERKLE_AUDIT_HOME` (por defecto `./.merkle-audit-client/`):

    manifest.key                    clave HMAC de 32 bytes, permisos 0600, nunca se registra
    manifests/<file_id>/<v>.json    un manifiesto sellado por (file_id, versión)
    responses/<audit_id>.json       cuerpo crudo de la respuesta (solo con --keep-responses)
    client.db                       bitácora y programas (ver auditlog.py)
"""

import contextlib
import os
import secrets
from pathlib import Path

from ..core.encoding import to_hex
from ..core.manifest import Manifest, dumps, loads, new_key
from ..core.params import KEY_SIZE

HOME_ENV = "MERKLE_AUDIT_HOME"
DEFAULT_HOME = ".merkle-audit-client"


class UnknownManifest(Exception):
    """No hay manifiesto local para ese archivo o esa versión: no se puede auditar."""


class ClientHome:
    def __init__(self, root: str | Path | None = None):
        self.root = Path(root or os.environ.get(HOME_ENV) or DEFAULT_HOME)
        self.root.mkdir(parents=True, exist_ok=True)

    @property
    def db_path(self) -> Path:
        return self.root / "client.db"

    # --- clave ---------------------------------------------------------------------------------

    @property
    def key_path(self) -> Path:
        return self.root / "manifest.key"

    def key(self) -> bytes:
        """La clave HMAC; se crea en el primer uso. Un archivo de clave dañado es un error duro."""
        if not self.key_path.exists():
            self._create_key()
        key = self.key_path.read_bytes()
        if len(key) != KEY_SIZE:
            raise RuntimeError(f"{self.key_path} no contiene una clave de {KEY_SIZE} bytes")
        return key

    def _create_key(self) -> None:
        # O_EXCL: si dos procesos arrancan a la vez, solo uno crea la clave y el otro la lee
        try:
            fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return
        with os.fdopen(fd, "wb") as f:
            f.write(new_key())

    # --- manifiestos ---------------------------------------------------------------------------

    def _manifest_dir(self, file_id: bytes) -> Path:
        return self.root / "manifests" / to_hex(file_id)

    def versions(self, file_id: bytes) -> list[int]:
        d = self._manifest_dir(file_id)
        if not d.is_dir():
            return []
        return sorted(int(p.stem) for p in d.glob("*.json") if p.stem.isdigit())

    def latest_version(self, file_id: bytes) -> int | None:
        found = self.versions(file_id)
        return found[-1] if found else None

    def file_ids(self) -> list[bytes]:
        d = self.root / "manifests"
        if not d.is_dir():
            return []
        return [bytes.fromhex(p.name) for p in sorted(d.iterdir()) if p.is_dir()]

    def save_manifest(self, manifest: Manifest) -> Path:
        """Guarda el manifiesto sellado. Una versión ya guardada no se sobrescribe."""
        d = self._manifest_dir(manifest.file_id)
        d.mkdir(parents=True, exist_ok=True)
        path = d / f"{manifest.version}.json"
        tmp = d / f".{manifest.version}.{secrets.token_hex(4)}.tmp"
        tmp.write_text(dumps(manifest, self.key()), encoding="utf-8")
        try:
            os.link(tmp, path)  # falla si ya existe: las versiones son inmutables
        except FileExistsError:
            raise FileExistsError(f"ya existe el manifiesto {path}") from None
        finally:
            with contextlib.suppress(OSError):
                tmp.unlink()
        return path

    def resolve_version(self, file_id: bytes, version: int | None) -> int:
        """La versión pedida o, por defecto, la última con manifiesto local."""
        if version is not None:
            return version
        latest = self.latest_version(file_id)
        if latest is None:
            raise UnknownManifest(f"no hay manifiestos para el archivo {to_hex(file_id)}")
        return latest

    def load_manifest(self, file_id: bytes, version: int | None = None) -> Manifest:
        """Carga y valida (§5.3) el manifiesto de una versión, por defecto la última.

        Lanza UnknownManifest si no existe y ManifestError si no valida.
        """
        version = self.resolve_version(file_id, version)
        path = self._manifest_dir(file_id) / f"{version}.json"
        if not path.is_file():
            raise UnknownManifest(f"no hay manifiesto de la versión {version}")
        return loads(path.read_bytes(), self.key())

    # --- respuestas ----------------------------------------------------------------------------

    def response_path(self, audit_id: str) -> Path:
        return self.root / "responses" / f"{audit_id}.json"

    def save_response(self, audit_id: str, raw: bytes) -> None:
        path = self.response_path(audit_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)

    def load_response(self, audit_id: str) -> bytes | None:
        path = self.response_path(audit_id)
        return path.read_bytes() if path.is_file() else None
