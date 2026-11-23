"""CLI del inyector de fallos (`merkle-audit-fault`).

Escribe directamente en el directorio de datos del servidor (`$MERKLE_AUDIT_SERVER_HOME` o
`--home`); no tiene endpoint de red. Ejemplos:

    merkle-audit-fault delete --file <hex> --indices 3 17
    merkle-audit-fault damage --file <hex> --eps 0.01 --op modify --seed 42
    merkle-audit-fault rollback --file <hex> --to 1 --lie
    merkle-audit-fault reset --file <hex>
"""

import argparse
import sys
from pathlib import Path

from ..core.encoding import EncodingError, from_hex, to_hex
from ..core.params import ID_SIZE
from .faults import Applied, DamageOp, FaultError, Injector, ModifyMode
from .store import Store


def _file_id(s: str) -> bytes:
    try:
        return from_hex(s, ID_SIZE)
    except EncodingError as e:
        raise argparse.ArgumentTypeError(f"file_id inválido: {e}") from e


def _eps(s: str) -> float:
    eps = float(s)
    if not 0 < eps <= 1:
        raise argparse.ArgumentTypeError("ε debe estar en (0, 1]")
    return eps


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="merkle-audit-fault",
        description="Daña a propósito el almacenamiento del servidor para probar las auditorías.",
    )
    parser.add_argument("--home", type=Path, help="directorio de datos del servidor")
    ops = parser.add_subparsers(dest="op", required=True, metavar="operación")

    def op(name: str, help: str, versioned: bool = True) -> argparse.ArgumentParser:
        p = ops.add_parser(name, help=help, description=help)
        p.add_argument("--file", required=True, type=_file_id, help="file_id en hex")
        if versioned:
            p.add_argument("--version", type=int, help="versión (por defecto, la última)")
        return p

    def seeded(p: argparse.ArgumentParser) -> None:
        p.add_argument("--seed", type=int, help="semilla (si no se da, se genera y se imprime)")

    p = op("delete", "borra bloques: el servidor responde block: null")
    p.add_argument("--indices", required=True, type=int, nargs="+")

    p = op("modify", "altera bloques: invierte un bit al azar o quita el último byte")
    p.add_argument("--indices", required=True, type=int, nargs="+")
    p.add_argument("--mode", choices=[m.value for m in ModifyMode], default="bitflip")
    seeded(p)

    p = op("replace", "el bloque --index pasa a tener el contenido del bloque --with")
    p.add_argument("--index", required=True, type=int)
    p.add_argument("--with", dest="other", required=True, type=int)

    p = op("cross-path", "al responder por --index, el servidor entrega el camino de --with")
    p.add_argument("--index", required=True, type=int)
    p.add_argument("--with", dest="other", required=True, type=int)

    p = op("rollback", "responde a la versión pedida con los datos de una anterior")
    p.add_argument("--to", required=True, type=int, help="versión anterior que se entrega")
    lie = p.add_mutually_exclusive_group(required=True)
    lie.add_argument("--declare", action="store_true", help="la respuesta dice la versión vieja")
    lie.add_argument("--lie", action="store_true", help="la respuesta dice la versión pedida")

    p = op("damage", "daña d = ⌈ε·n⌉ bloques elegidos al azar")
    p.add_argument("--eps", required=True, type=_eps)
    p.add_argument("--op", dest="damage_op", required=True, choices=[o.value for o in DamageOp])
    p.add_argument("--mode", choices=[m.value for m in ModifyMode], default="bitflip")
    seeded(p)

    op("drop-file", "borra el archivo entero (se puede deshacer con reset)", versioned=False)
    op("reset", "vuelve al estado de la carga y desactiva los fallos", versioned=False)
    return parser


def run(args: argparse.Namespace, injector: Injector) -> Applied:
    f, v = args.file, getattr(args, "version", None)
    match args.op:
        case "delete":
            return injector.delete(f, args.indices, version=v)
        case "modify":
            return injector.modify(f, args.indices, ModifyMode(args.mode), args.seed, version=v)
        case "replace":
            return injector.replace(f, args.index, args.other, version=v)
        case "cross-path":
            return injector.cross_path(f, args.index, args.other, version=v)
        case "rollback":
            return injector.rollback(f, args.to, declare=args.declare, version=v)
        case "damage":
            return injector.damage(
                f, args.eps, DamageOp(args.damage_op), ModifyMode(args.mode), args.seed, version=v
            )
        case "drop-file":
            return injector.drop_file(f)
        case "reset":
            return injector.reset(f)
    raise AssertionError(args.op)


def describe(applied: Applied) -> str:
    target = to_hex(applied.file_id)
    if applied.version is not None:
        target += f" v{applied.version}"
    lines = [f"{applied.op} aplicado a {target} (registro #{applied.fault_id})"]
    if applied.indices:
        shown = applied.indices[:20]
        more = f" … y {len(applied.indices) - 20} más" if len(applied.indices) > 20 else ""
        lines.append(f"índices ({len(applied.indices)}): {shown}{more}")
    if applied.seed is not None:
        lines.append(f"semilla: {applied.seed}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    # una consola con codificación limitada (cp1252 en Windows) no debe tumbar el CLI al imprimir;
    # sin esto, la ayuda falla y una falta ya aplicada termina con un traceback al describirla
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    try:
        applied = run(args, Injector(Store(args.home)))
    except FaultError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(describe(applied))
    return 0


if __name__ == "__main__":
    sys.exit(main())
