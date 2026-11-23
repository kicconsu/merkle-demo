"""Los CLI no se caen en una consola con codificación limitada (cp1252, la de Windows por defecto).

Ayuda y mensajes usan caracteres como «ε», «→» o «…» que cp1252 no puede codificar; antes, la ayuda
de `merkle-audit-fault` terminaba en UnicodeEncodeError.
"""

import io
import sys

import pytest

from merkle_audit.client import cli as client_cli
from merkle_audit.server import fault_cli


@pytest.mark.parametrize("main", [client_cli.main, fault_cli.main], ids=["cliente", "inyector"])
def test_help_prints_on_a_cp1252_console(monkeypatch, main):
    # la consola se sustituye aquí y no en un fixture: pytest restaura su propia captura de
    # sys.stdout entre la preparación de los fixtures y la ejecución del test
    out = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    err = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    out.flush()
    assert exc.value.code == 0
    assert out.buffer.getvalue().startswith(b"usage: ")
