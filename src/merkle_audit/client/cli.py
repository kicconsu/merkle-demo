"""CLI `merkle-audit`: carga, auditoría, bitácora y programador.

Códigos de salida de `audit`: 0 PASS, 1 CORRUPT, 2 INVALID, 3 INCOMPLETE. Los errores de uso o de
entorno (archivo inexistente, sin manifiesto, carga fallida) salen con 64.
"""

import argparse
import json
import sys
from collections.abc import Sequence

from ..core.encoding import EncodingError, from_hex, to_hex
from ..core.params import BLOCK_SIZES, DEFAULT_BLOCK_SIZE, DEFAULT_TIMEOUT_S
from .auditlog import AuditLog
from .auditor import AuditRecord, UploadError, reverify, run_audit, upload_file
from .scheduler import add_schedule, run_due, run_loop
from .storage import ClientHome, UnknownManifest
from .transport import DEFAULT_SERVER, HttpTransport

EXIT_BY_STATUS = {"PASS": 0, "CORRUPT": 1, "INVALID": 2, "INCOMPLETE": 3}
EXIT_USAGE = 64


class CliError(Exception):
    pass


def _file_id(text: str) -> bytes:
    try:
        return from_hex(text, 16)
    except EncodingError as e:
        raise CliError(f"file_id inválido: {e}") from e


def _out(*parts) -> None:
    print(*parts)


def _describe(record: AuditRecord) -> str:
    r, row = record.result, record.row
    head = f"{r.status.value}  audit_id={record.audit_id}  versión={record.version}"
    if row["q"] is not None:
        head += f"  q={row['q']}/{row['n']}"
    lines = [head]
    if r.trivial:
        lines.append("  archivo vacío: PASS trivial, no había bloques que muestrear")
    for f in r.findings:
        where = f"índice {f.index}" if f.index is not None else "respuesta"
        lines.append(f"  {f.cause.value}  ({where}){'  ' + f.detail if f.detail else ''}")
    if row["theory"] and r.status.value == "PASS":
        theory = ", ".join(f"eps={k}: {v:.4f}" for k, v in row["theory"].items())
        lines.append(f"  P(detección) con este q según la fracción dañada: {theory}")
        lines.append("  PASS es evidencia probabilística sobre los bloques consultados, no prueba")
        lines.append("  de que el archivo completo esté disponible.")
    if row["latency_ms"] is not None:
        lines.append(
            f"  latencia {row['latency_ms']:.1f} ms · desafío {row['challenge_bytes']} B"
            f" · respuesta {row['response_bytes'] or 0} B"
        )
    return "\n".join(lines)


# --- Comandos -----------------------------------------------------------------------------------


def cmd_upload(args, home: ClientHome, log: AuditLog, transport: HttpTransport) -> int:
    file_id = _file_id(args.file_id) if args.file_id else None
    try:
        m = upload_file(home, transport, args.path, file_id=file_id, block_size=args.block_size)
    except (UploadError, OSError, ValueError) as e:
        raise CliError(str(e)) from e
    _out(f"file_id   {to_hex(m.file_id)}")
    _out(f"versión   {m.version}")
    _out(f"bloques   {m.n_blocks} de {m.block_size} B ({m.file_size} B)")
    _out(f"raíz      {to_hex(m.root)}")
    return 0


def cmd_audit(args, home: ClientHome, log: AuditLog, transport: HttpTransport) -> int:
    try:
        record = run_audit(
            home,
            log,
            transport,
            _file_id(args.file_id),
            version=args.version,
            q=args.q,
            eps=args.target_eps,
            confidence=args.confidence,
            timeout_s=args.timeout,
            keep_responses=args.keep_responses,
        )
    except UnknownManifest as e:
        raise CliError(str(e)) from e
    except ValueError as e:  # q fuera de rango para este archivo
        raise CliError(str(e)) from e
    _out(_describe(record))
    return EXIT_BY_STATUS[record.result.status.value]


def cmd_reverify(args, home: ClientHome, log: AuditLog, transport: HttpTransport) -> int:
    try:
        result = reverify(home, log, args.audit_id)
    except (KeyError, FileNotFoundError, ValueError) as e:
        raise CliError(str(e.args[0] if isinstance(e, KeyError) else e)) from e
    _out(f"reverificación: {result.status.value}")
    for f in result.findings:
        _out(f"  {f.cause.value}" + (f"  (índice {f.index})" if f.index is not None else ""))
    return EXIT_BY_STATUS[result.status.value]


def cmd_log(args, home: ClientHome, log: AuditLog, transport: HttpTransport) -> int:
    rows = log.list_audits(args.file_id, args.limit)
    if args.json:
        _out(json.dumps(rows, indent=2))
        return 0
    for r in rows:
        causes = ",".join(sorted({f["cause"] for f in r["findings"]})) or "-"
        _out(
            f"{r['started_at']}  {r['status']:<10} {r['audit_id']}  v{r['version']}"
            f"  q={r['q']}  {r['origin']}  {causes}"
        )
    return 0


def cmd_files(args, home: ClientHome, log: AuditLog, transport: HttpTransport) -> int:
    for fid in home.file_ids():
        for v in home.versions(fid):
            _out(f"{to_hex(fid)}  v{v}")
    return 0


def cmd_schedule(args, home: ClientHome, log: AuditLog, transport: HttpTransport) -> int:
    action = args.schedule_cmd
    if action == "add":
        try:
            sid = add_schedule(
                log,
                file_id=args.file_id,
                every=args.every,
                q=args.q,
                target_eps=args.target_eps,
                confidence=args.confidence,
                timeout_s=args.timeout,
            )
        except (ValueError, EncodingError) as e:
            raise CliError(str(e)) from e
        _out(f"programa {sid} creado")
    elif action == "list":
        for s in log.list_schedules():
            goal = f"q={s.q}" if s.q else f"eps={s.target_eps or 0.01} conf={s.confidence or 0.99}"
            _out(
                f"{s.id}  {s.file_id}  cada {s.every_s:g}s  {goal}  última: {s.last_run_at or '-'}"
            )
    elif action == "remove":
        if not log.remove_schedule(args.id):
            raise CliError(f"no existe el programa {args.id}")
        _out(f"programa {args.id} eliminado")
    elif action == "run":
        if args.once:
            records = run_due(home, log, transport, keep_responses=args.keep_responses)
            for r in records:
                _out(_describe(r))
        else:
            try:
                run_loop(
                    home,
                    log,
                    transport,
                    keep_responses=args.keep_responses,
                    on_record=lambda r: _out(_describe(r)),
                )
            except KeyboardInterrupt:
                _out("programador detenido")
    return 0


# --- Argumentos ---------------------------------------------------------------------------------


def _add_q_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("--q", type=int, help="bloques a consultar")
    p.add_argument("--target-eps", type=float, help="fracción de bloques dañados a detectar (0.01)")
    p.add_argument("--confidence", type=float, help="probabilidad de detección buscada (0.99)")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S, help="segundos de espera")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="merkle-audit", description=__doc__.splitlines()[0])
    p.add_argument("--home", help="directorio de datos (por defecto $MERKLE_AUDIT_HOME)")
    p.add_argument("--server", help=f"URL del servidor (por defecto {DEFAULT_SERVER})")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("upload", help="sube un archivo y guarda su manifiesto")
    s.add_argument("path")
    s.add_argument("--file-id", help="subir una versión nueva de este archivo")
    s.add_argument("--block-size", type=int, default=DEFAULT_BLOCK_SIZE, choices=BLOCK_SIZES)
    s.set_defaults(func=cmd_upload)

    s = sub.add_parser("audit", help="audita una versión de un archivo")
    s.add_argument("--file-id", required=True)
    s.add_argument("--version", type=int, help="por defecto, la última")
    _add_q_options(s)
    s.add_argument("--keep-responses", action="store_true", help="solo para datos sintéticos")
    s.set_defaults(func=cmd_audit)

    s = sub.add_parser("reverify", help="repite la verificación de una respuesta guardada")
    s.add_argument("audit_id")
    s.set_defaults(func=cmd_reverify)

    s = sub.add_parser("log", help="muestra la bitácora de auditorías")
    s.add_argument("--file-id")
    s.add_argument("--limit", type=int, default=20)
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_log)

    s = sub.add_parser("files", help="lista los archivos y versiones con manifiesto local")
    s.set_defaults(func=cmd_files)

    s = sub.add_parser("schedule", help="auditorías periódicas")
    ssub = s.add_subparsers(dest="schedule_cmd", required=True)
    a = ssub.add_parser("add")
    a.add_argument("--file-id", required=True)
    a.add_argument("--every", required=True, help="30s, 10m, 2h, 1d")
    _add_q_options(a)
    ssub.add_parser("list")
    r = ssub.add_parser("remove")
    r.add_argument("id", type=int)
    r = ssub.add_parser("run", help="ejecuta los programas vencidos")
    r.add_argument("--once", action="store_true", help="una pasada y salir")
    r.add_argument("--keep-responses", action="store_true")
    s.set_defaults(func=cmd_schedule)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    # una consola con codificación limitada (cp1252 en Windows) no debe tumbar el CLI al imprimir
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    home = ClientHome(args.home)
    log = AuditLog(home.db_path)
    transport = HttpTransport(args.server)
    try:
        return args.func(args, home, log, transport)
    except CliError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_USAGE
    finally:
        transport.close()


if __name__ == "__main__":
    sys.exit(main())
