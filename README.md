# merkle-demo

**Proyecto 7: auditor probabilístico de integridad para almacenamiento en la nube** con árboles de Merkle. Equipo 12, Criptografía Aplicada (Uninorte).

Integrantes: Fatima Castro, Juan David Borja, Samuel Camargo

## Por dónde empezar
1. [`docs/spec.md`](docs/spec.md): **el contrato**. Fija formatos, mensajes y reglas de rechazo. El código lo implementa byte a byte.
2. [`informe/`](informe/): informe final (LaTeX).

## Estructura
```
docs/                 spec (contrato normativo)
src/merkle_audit/
  core/               primitivas puras, sin red ni disco: codificación, Merkle, manifiesto, probabilidad
  protocol/           mensajes (pydantic), generación de desafíos, verificación de respuestas, estados
  server/             API FastAPI, almacén de bloques, inyector de fallos
  client/             CLI, persistencia SQLite (manifiestos y bitácora), programador, transporte httpx
  ui/                 panel Streamlit
tests/
  unit/               core y protocol, sin red
  integration/        cliente ↔ servidor de punta a punta
  adversarial/        un test por cada ataque del plan (borrado, sustitución, camino cruzado, rollback…)
experiments/          scripts reproducibles; results/ guarda los CSV que se versionan
scripts/demo.py       demostración de punta a punta (make demo)
informe/              informe final E2 (LaTeX)
```

**Regla de dependencias:** `core ← protocol ← {client, server} ← ui`. `core` no importa nada de red, disco ni frameworks. Por eso se puede probar exhaustivamente y es lo que más importa en la nota de criptografía aplicada. Así se separan interfaz, protocolo, primitivas, persistencia y pruebas.

## Instalación
Requiere [uv](https://docs.astral.sh/uv/). Las dependencias quedan fijadas en `uv.lock`.
```
uv sync            # crea .venv con Python 3.12 y todo fijado
make check         # lint + tests
```
Comandos frecuentes: `make test`, `make lint`, `make fmt`, `make server`, `make ui`.

### Sin `make` (Windows)
Windows no trae `make`. Cada objetivo del `Makefile` es uno o varios comandos `uv run`, que se pueden escribir directamente desde la raíz del repo:

| Con `make` | Sin `make` |
|---|---|
| `make sync` | `uv sync` |
| `make test` | `uv run pytest` |
| `make lint` | `uv run ruff check .` y `uv run ruff format --check .` |
| `make fmt` | `uv run ruff check --fix .` y `uv run ruff format .` |
| `make check` | los dos comandos de `make lint` y luego `uv run pytest` |
| `make server` | `uv run uvicorn merkle_audit.server.app:app --reload` |
| `make ui` | `uv run streamlit run src/merkle_audit/ui/app.py` |
| `make demo` | `uv run python scripts/demo.py` |
| `make experiments` | `uv run python experiments/run_detection.py`, luego `uv run python experiments/run_costs.py` y `uv run python experiments/plot_results.py` |

Dos tropiezos posibles en Windows:
- **`uv: command not found`.** Instálelo con el instalador oficial, que lo añade al `PATH` (abra una terminal nueva después):
  ```
  powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
  ```
  En Git Bash o MSYS2, si sigue sin aparecer, añada `/c/Users/<usuario>/.local/bin` al `PATH` en `~/.bashrc`.
- **«Una directiva de Control de aplicaciones bloqueó este archivo».** Algunas políticas de Windows (Smart App Control) bloquean los ejecutables que `uv` genera para `merkle-audit` y `merkle-audit-fault`. Los mismos CLI se pueden llamar como módulos de Python, con los mismos argumentos:
  ```
  uv run python -m merkle_audit.client.cli ...        # en vez de: uv run merkle-audit ...
  uv run python -m merkle_audit.server.fault_cli ...  # en vez de: uv run merkle-audit-fault ...
  ```

## Servidor e inyector de fallos
`make server` levanta la API en `http://127.0.0.1:8000`. Guarda sus datos en `$MERKLE_AUDIT_SERVER_HOME` (por defecto `./.merkle-audit-server/`).

El inyector escribe en ese mismo directorio, también con el servidor encendido:
```
uv run merkle-audit-fault delete     --file <file_id> --indices 3 17
uv run merkle-audit-fault modify     --file <file_id> --indices 5 [--mode bitflip|truncate] [--seed S]
uv run merkle-audit-fault replace    --file <file_id> --index 5 --with 6
uv run merkle-audit-fault cross-path --file <file_id> --index 0 --with 19
uv run merkle-audit-fault rollback   --file <file_id> --to 1 --declare|--lie
uv run merkle-audit-fault damage     --file <file_id> --eps 0.01 --op delete|modify [--seed S]
uv run merkle-audit-fault drop-file  --file <file_id>
uv run merkle-audit-fault reset      --file <file_id>
```
Todas las operaciones aceptan `--version v` (por defecto, la última), salvo `drop-file` y `reset`. Para usar otro directorio, se pasa `--home DIR` antes de la operación.

## Cliente
Con el servidor encendido (`make server`), el cliente guarda clave, manifiestos y bitácora en `$MERKLE_AUDIT_HOME` (por defecto `./.merkle-audit-client/`). `--server URL` o `$MERKLE_AUDIT_SERVER` cambian el servidor.
```
uv run merkle-audit upload datos.bin [--file-id <id>] [--block-size 4096]
uv run merkle-audit audit --file-id <id> [--version v] [--q 300 | --target-eps 0.01 --confidence 0.99] [--keep-responses]
uv run merkle-audit reverify <audit_id>
uv run merkle-audit log [--file-id <id>] [--json]
uv run merkle-audit schedule add --file-id <id> --every 10m --q 300
uv run merkle-audit schedule run [--once]
```
`audit` sale con 0 (PASS), 1 (CORRUPT), 2 (INVALID) o 3 (INCOMPLETE).

## Demostración
**Automática (≈30 s).** `make demo` levanta un servidor propio con directorios temporales y recorre los casos del enunciado con los mismos CLI de abajo. Cada paso declara el estado que espera y el script sale con código distinto de cero si alguno no coincide. Los datos son sintéticos y salen de `--seed` (por defecto 2026); con `--keep` los directorios quedan para abrirlos con `make ui`.

**Guion manual** (tres terminales; el cliente usa `./.merkle-audit-client/` y el servidor `./.merkle-audit-server/`):

1. *Servidor.* `make server`.
2. *Archivo intacto.* Con cualquier archivo `datos.bin`:
   ```
   uv run merkle-audit upload datos.bin          # imprime el file_id y la raíz
   uv run merkle-audit audit --file-id <id>      # PASS; muestra P(detección) y el costo
   ```
3. *Borrado y modificación* (`--eps 0.10` daña el 10 % de los bloques; `reset` restaura):
   ```
   uv run merkle-audit-fault damage --file <id> --eps 0.10 --op delete --seed 1
   uv run merkle-audit audit --file-id <id>      # CORRUPT · BLOCK_MISSING, con cada índice
   uv run merkle-audit-fault reset --file <id>
   uv run merkle-audit-fault damage --file <id> --eps 0.10 --op modify --seed 2
   uv run merkle-audit audit --file-id <id>      # CORRUPT · ROOT_MISMATCH
   uv run merkle-audit-fault reset --file <id>
   ```
4. *Límite del muestreo.* Un solo bloque dañado se ve con probabilidad `q/n`:
   ```
   uv run merkle-audit-fault modify --file <id> --indices 7
   uv run merkle-audit audit --file-id <id> --q 100   # puede dar PASS: no se muestreó ese bloque
   uv run merkle-audit audit --file-id <id> --q 1024  # más q, más probabilidad de verlo
   ```
5. *Reemplazo, camino cruzado y rollback* (con un archivo de ~64 bloques y `--q 64`, la auditoría es completa):
   ```
   uv run merkle-audit-fault replace    --file <id> --index 5 --with 6
   uv run merkle-audit-fault cross-path --file <id> --index 0 --with 40
   uv run merkle-audit upload datos2.bin --file-id <id>             # versión 2
   uv run merkle-audit-fault rollback   --file <id> --to 1 --declare   # INVALID · VERSION_MISMATCH
   uv run merkle-audit-fault rollback   --file <id> --to 1 --lie       # CORRUPT · ROOT_MISMATCH
   ```
6. *Manifiesto alterado.* Cambiar cualquier campo de `.merkle-audit-client/manifests/<id>/1.json` y auditar: `INVALID · MANIFEST_MAC`, sin enviar el desafío.
7. *Reverificación y bitácora.* `merkle-audit audit … --keep-responses`, luego `merkle-audit reverify <audit_id>` y `merkle-audit log`.
8. *Servidor caído.* Detener `make server` y auditar: `INCOMPLETE`, que no cuenta como evidencia.
9. *Panel.* `make ui` abre el panel: curvas de probabilidad y costo según `q`, historial con la evidencia de cada auditoría y programas.

Una serie de PASS es evidencia probabilística sobre los bloques consultados, no una prueba de que el archivo completo esté disponible (spec §1, §10.3).
