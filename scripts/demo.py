"""Demostración reproducible de punta a punta, con los mismos CLI que usa una persona.

Levanta un servidor propio en un puerto libre, con directorios temporales, y recorre los casos del
enunciado: archivos intactos, vacíos y de tamaño no múltiplo del bloque; bloques borrados,
modificados, reemplazados o con el camino de otro índice; un manifiesto alterado; una respuesta de
una versión anterior; la pérdida del archivo y un servidor caído. Cada paso declara el estado que
espera y la demo termina con código distinto de cero si alguno no coincide.

    uv run python scripts/demo.py [--keep] [--seed 2026] [--big-blocks 2048]

Los datos son sintéticos y salen de la semilla. Con `--keep` los directorios no se borran y el
script imprime dónde quedaron, para abrirlos con `make ui`.
"""

import argparse
import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

BLOCK = 4096
STATUS_BY_EXIT = {0: "PASS", 1: "CORRUPT", 2: "INVALID", 3: "INCOMPLETE"}

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


class Demo:
    def __init__(self, root: Path, seed: int, big_blocks: int):
        self.root = root
        self.seed = seed
        self.big_blocks = big_blocks
        self.client_home = root / "client"
        self.server_home = root / "server"
        self.port = _free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.env = {
            **os.environ,
            "MERKLE_AUDIT_SERVER_HOME": str(self.server_home),
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUTF8": "1",
        }
        self.server: subprocess.Popen | None = None
        self.results: list[tuple[str, str, str, bool]] = []

    # --- procesos ------------------------------------------------------------------------------

    def start_server(self) -> None:
        self.server = subprocess.Popen(  # noqa: S603
            [
                sys.executable,
                "-m",
                "uvicorn",
                "merkle_audit.server.app:app",
                "--port",
                str(self.port),
                "--log-level",
                "warning",
            ],
            env=self.env,
        )
        for _ in range(100):
            try:
                httpx.get(self.url + "/", timeout=1.0)
                return
            except httpx.HTTPError:
                time.sleep(0.1)
        raise RuntimeError("el servidor no arrancó")

    def stop_server(self) -> None:
        if self.server and self.server.poll() is None:
            self.server.terminate()
            try:
                self.server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.server.kill()

    def _run(self, module: str, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(  # noqa: S603
            [sys.executable, "-m", module, *args],
            env=self.env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )

    def client(self, *args: str) -> subprocess.CompletedProcess:
        return self._run(
            "merkle_audit.client.cli", "--home", str(self.client_home), "--server", self.url, *args
        )

    def fault(self, op: str, file_id: str, *args: str) -> str:
        p = self._run(
            "merkle_audit.server.fault_cli",
            "--home",
            str(self.server_home),
            op,
            "--file",
            file_id,
            *args,
        )
        if p.returncode != 0:
            raise RuntimeError(f"fallo del inyector ({op}): {p.stderr.strip()}")
        return p.stdout.strip().splitlines()[0] if p.stdout.strip() else ""

    # --- pasos ---------------------------------------------------------------------------------

    def say(self, text: str) -> None:
        print(f"\n== {text}")

    def upload(self, path: Path, *args: str) -> str:
        p = self.client("upload", str(path), *args)
        if p.returncode != 0:
            raise RuntimeError(f"la carga falló: {p.stderr.strip()}")
        print("   " + p.stdout.strip().replace("\n", "\n   "))
        m = re.search(r"file_id\s+([0-9a-f]{32})", p.stdout)
        assert m, p.stdout
        return m.group(1)

    def audit(
        self,
        label: str,
        file_id: str,
        expect: str | set[str],
        causes: set[str] | None = None,
        *args: str,
    ) -> str:
        """Audita, muestra el resultado y comprueba estado y causas esperados."""
        p = self.client("audit", "--file-id", file_id, *args)
        status = STATUS_BY_EXIT.get(p.returncode, f"salida {p.returncode}")
        found = set(re.findall(r"^\s+([A-Z_]+)\s+\(", p.stdout, re.M))
        wanted = {expect} if isinstance(expect, str) else expect
        # con causas esperadas, al menos una debe aparecer (salvo que el resultado sea PASS)
        ok = status in wanted and (not causes or status == "PASS" or bool(causes & found))
        print(f"   {label}: {status}  {', '.join(sorted(found)) or ''}".rstrip())
        self.results.append((label, status, "/".join(sorted(wanted)), ok))
        audit_id = re.search(r"audit_id=([0-9a-f]{32})", p.stdout)
        return audit_id.group(1) if audit_id else ""

    # --- guion ---------------------------------------------------------------------------------

    def run(self) -> bool:
        rng = random.Random(self.seed)  # noqa: S311 (datos sintéticos repetibles)
        data = self.root / "data"
        data.mkdir()
        big = data / "grande.bin"
        big.write_bytes(rng.randbytes(self.big_blocks * BLOCK - 321))
        small = data / "pequeno.bin"
        small.write_bytes(rng.randbytes(64 * BLOCK))
        small_v2 = data / "pequeno_v2.bin"
        small_v2.write_bytes(rng.randbytes(64 * BLOCK))
        odd = data / "impar.bin"
        odd.write_bytes(rng.randbytes(3 * BLOCK + 17))
        empty = data / "vacio.bin"
        empty.write_bytes(b"")

        self.say("1. Servidor y cargas")
        self.start_server()
        print(f"   servidor en {self.url}")
        fid_big = self.upload(big)
        fid_small = self.upload(small)
        fid_odd = self.upload(odd)
        fid_empty = self.upload(empty)

        self.say("2. Archivos intactos, impares y vacíos: PASS")
        self.audit("grande (q para ε=1 %, 99 %)", fid_big, "PASS")
        self.audit("pequeño, todos los bloques", fid_small, "PASS", None, "--q", "64")
        self.audit("tamaño no múltiplo del bloque", fid_odd, "PASS", None, "--q", "4")
        self.audit("archivo vacío (PASS trivial)", fid_empty, "PASS")

        self.say("3. Daño del 10 % en el archivo grande, con q para ε = 1 %")
        print(
            "   " + self.fault("damage", fid_big, "--eps", "0.10", "--op", "delete", "--seed", "1")
        )
        self.audit("bloques borrados", fid_big, "CORRUPT", {"BLOCK_MISSING"})
        self.fault("reset", fid_big)
        print(
            "   " + self.fault("damage", fid_big, "--eps", "0.10", "--op", "modify", "--seed", "2")
        )
        self.audit("bloques modificados", fid_big, "CORRUPT", {"ROOT_MISMATCH", "BLOCK_LENGTH"})
        self.fault("reset", fid_big)
        self.audit("tras reset", fid_big, "PASS")

        self.say("4. Límite del muestreo: un solo bloque dañado en el archivo grande")
        self.fault("modify", fid_big, "--indices", "7", "--seed", "3")
        n = self.big_blocks
        print(f"   con q = 300 de n = {n}, la probabilidad de verlo es 300/{n} = {300 / n:.1%}")
        self.audit("1 bloque dañado, q = 300", fid_big, {"PASS", "CORRUPT"}, None, "--q", "300")
        print("   un PASS aquí no prueba que el archivo esté íntegro, solo que no se muestreó")
        self.audit("el mismo daño, q = 1024", fid_big, {"PASS", "CORRUPT"}, None, "--q", "1024")
        self.fault("reset", fid_big)

        self.say("5. Un bloque reemplazado o con el camino de otro: auditoría completa (q = n)")
        self.fault("replace", fid_small, "--index", "5", "--with", "6")
        self.audit("bloque reemplazado", fid_small, "CORRUPT", {"ROOT_MISMATCH"}, "--q", "64")
        self.fault("reset", fid_small)
        self.fault("cross-path", fid_small, "--index", "0", "--with", "40")
        self.audit(
            "camino de otro índice",
            fid_small,
            "CORRUPT",
            {"ROOT_MISMATCH", "PATH_LENGTH"},
            "--q",
            "64",
        )
        self.fault("reset", fid_small)

        self.say("6. Versiones y rollback")
        v2 = self.upload(small_v2, "--file-id", fid_small)
        assert v2 == fid_small
        self.audit("versión 2 intacta", fid_small, "PASS", None, "--q", "64")
        self.fault("rollback", fid_small, "--to", "1", "--lie")
        self.audit(
            "rollback que miente la versión", fid_small, "CORRUPT", {"ROOT_MISMATCH"}, "--q", "64"
        )
        self.fault("reset", fid_small)
        self.fault("rollback", fid_small, "--to", "1", "--declare")
        self.audit(
            "rollback que declara la versión vieja",
            fid_small,
            "INVALID",
            {"VERSION_MISMATCH"},
            "--q",
            "64",
        )
        self.fault("reset", fid_small)

        self.say("7. Pérdida del archivo en el servidor")
        self.fault("drop-file", fid_small)
        self.audit("archivo borrado", fid_small, "CORRUPT", {"FILE_MISSING"}, "--q", "8")
        self.fault("reset", fid_small)
        self.audit("tras reset", fid_small, "PASS", None, "--q", "8")

        self.say("8. Manifiesto alterado en el cliente: no se envía ningún desafío")
        mpath = self.client_home / "manifests" / fid_odd / "1.json"
        original = mpath.read_text(encoding="utf-8")
        doc = json.loads(original)
        doc["root"] = "ab" * 32
        mpath.write_text(json.dumps(doc), encoding="utf-8")
        self.audit("raíz del manifiesto cambiada", fid_odd, "INVALID", {"MANIFEST_MAC"}, "--q", "4")
        mpath.write_text(original, encoding="utf-8")

        self.say("9. Reverificar una respuesta guardada")
        self.fault("modify", fid_odd, "--indices", "1", "--seed", "4")
        audit_id = self.audit(
            "auditoría con --keep-responses",
            fid_odd,
            "CORRUPT",
            {"ROOT_MISMATCH"},
            "--q",
            "4",
            "--keep-responses",
        )
        p = self.client("reverify", audit_id)
        again = p.stdout.splitlines()[0] if p.stdout else p.stderr
        ok = p.returncode == 1
        print(f"   {again}")
        self.results.append(
            ("reverify repite el veredicto", "CORRUPT" if ok else again, "CORRUPT", ok)
        )
        self.fault("reset", fid_odd)

        self.say("10. Servidor caído: INCOMPLETE, que no cuenta como evidencia")
        self.stop_server()
        self.audit(
            "sin servidor", fid_big, "INCOMPLETE", {"CONNECTION", "TIMEOUT"}, "--timeout", "3"
        )

        self.say("Bitácora (últimas 6)")
        print("   " + self.client("log", "--limit", "6").stdout.strip().replace("\n", "\n   "))
        return self.summary()

    def summary(self) -> bool:
        print("\n== Resumen")
        width = max(len(r[0]) for r in self.results)
        for label, got, want, ok in self.results:
            print(f"   {'ok ' if ok else 'MAL'}  {label:<{width}}  {got}  (esperado: {want})")
        failed = [r for r in self.results if not r[3]]
        print(f"\n   {len(self.results) - len(failed)}/{len(self.results)} pasos como se esperaba")
        return not failed


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--big-blocks", type=int, default=2048, help="bloques del archivo grande")
    ap.add_argument("--keep", action="store_true", help="conservar los directorios de datos")
    args = ap.parse_args(argv)
    if args.big_blocks < 1100:
        ap.error("--big-blocks debe ser ≥ 1100 para que el caso del bloque único sea ilustrativo")

    root = Path(tempfile.mkdtemp(prefix="merkle-audit-demo-"))
    demo = Demo(root, args.seed, args.big_blocks)
    try:
        ok = demo.run()
    finally:
        demo.stop_server()
        if args.keep:
            print(f"\nDatos conservados en {root}")
            print(f"  MERKLE_AUDIT_HOME={demo.client_home}")
        else:
            shutil.rmtree(root, ignore_errors=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
