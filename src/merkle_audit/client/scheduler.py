"""Programador de auditorías periódicas (§9.2).

Cada ejecución es una auditoría normal, con índices nuevos, registrada con `origin = schedule:<id>`.
Los programas viven en la tabla `schedules`; `run_due` ejecuta los vencidos y `run_loop` repite
hasta que se le pida parar.
"""

import re
import time
from collections.abc import Callable
from datetime import UTC, datetime

from ..core.encoding import from_hex
from ..core.params import DEFAULT_TIMEOUT_S
from .auditlog import AuditLog, Schedule
from .auditor import AuditRecord, now_rfc3339, run_audit
from .storage import ClientHome, UnknownManifest
from .transport import HttpTransport

_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_every(text: str) -> float:
    """'30s', '10m', '2h' o '1d' → segundos. Debe ser positivo."""
    m = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([smhd])", text.strip())
    if not m or float(m.group(1)) <= 0:
        raise ValueError(f"intervalo inválido {text!r}; use por ejemplo 30s, 10m, 2h o 1d")
    return float(m.group(1)) * _UNITS[m.group(2)]


def add_schedule(
    log: AuditLog,
    *,
    file_id: str,
    every: str,
    q: int | None = None,
    target_eps: float | None = None,
    confidence: float | None = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> int:
    from_hex(file_id, 16)  # valida forma y longitud
    if q is not None and target_eps is not None:
        raise ValueError("use --q o --target-eps, no ambos")
    if q is not None and q < 1:
        raise ValueError("q debe ser ≥ 1")
    if target_eps is not None and not 0 < target_eps <= 1:
        raise ValueError("--target-eps debe estar en (0, 1]")
    if confidence is not None and not 0 < confidence < 1:
        raise ValueError("--confidence debe estar en (0, 1)")
    return log.add_schedule(
        file_id=file_id,
        every_s=parse_every(every),
        q=q,
        target_eps=target_eps,
        confidence=confidence,
        timeout_s=timeout_s,
        created_at=now_rfc3339(),
    )


def _epoch(stamp: str) -> float:
    return datetime.fromisoformat(stamp.replace("Z", "+00:00")).astimezone(UTC).timestamp()


def next_due(s: Schedule) -> float:
    """Instante (epoch) de la próxima ejecución: un intervalo después de la última, o de la alta."""
    return _epoch(s.last_run_at or s.created_at) + s.every_s


def run_schedule(
    home: ClientHome,
    log: AuditLog,
    transport: HttpTransport,
    s: Schedule,
    *,
    keep_responses: bool = False,
) -> AuditRecord:
    record = run_audit(
        home,
        log,
        transport,
        bytes.fromhex(s.file_id),
        q=s.q,
        eps=s.target_eps,
        confidence=s.confidence,
        timeout_s=s.timeout_s,
        origin=f"schedule:{s.id}",
        keep_responses=keep_responses,
    )
    log.mark_schedule_run(s.id, now_rfc3339())
    return record


def run_due(
    home: ClientHome,
    log: AuditLog,
    transport: HttpTransport,
    *,
    now: float | None = None,
    keep_responses: bool = False,
) -> list[AuditRecord]:
    """Ejecuta una vez cada programa vencido. Un programa sin manifiesto local se omite."""
    now = time.time() if now is None else now
    records = []
    for s in log.list_schedules():
        if next_due(s) > now:
            continue
        try:
            records.append(run_schedule(home, log, transport, s, keep_responses=keep_responses))
        except UnknownManifest:
            continue
    return records


def run_loop(
    home: ClientHome,
    log: AuditLog,
    transport: HttpTransport,
    *,
    keep_responses: bool = False,
    on_record: Callable[[AuditRecord], None] = lambda r: None,
    max_rounds: int | None = None,
    sleep: Callable[[float], None] = time.sleep,
    poll_s: float = 1.0,
) -> None:
    """Revisa los programas cada `poll_s` segundos hasta `max_rounds` revisiones (o sin fin)."""
    rounds = 0
    while max_rounds is None or rounds < max_rounds:
        for record in run_due(home, log, transport, keep_responses=keep_responses):
            on_record(record)
        rounds += 1
        if max_rounds is None or rounds < max_rounds:
            sleep(poll_s)
