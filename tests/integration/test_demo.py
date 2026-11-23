"""La demo reproducible no se desactualiza: corre completa y cada paso sale como se espera."""

import importlib.util
from pathlib import Path

DEMO = Path(__file__).parents[2] / "scripts" / "demo.py"


def test_demo_script_runs_end_to_end(capsys):
    spec = importlib.util.spec_from_file_location("demo_script", DEMO)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    code = module.main(["--big-blocks", "1100"])
    out = capsys.readouterr().out
    assert code == 0, out
    assert "pasos como se esperaba" in out
