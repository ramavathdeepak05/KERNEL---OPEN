"""The base install must be enough to govern actions in-process and to run `quaicu init`.

`pip install .` brings only cel-python, cryptography and the OpenTelemetry API. The web framework,
the JWT library, the HTTP client and the database drivers are extras, so nothing on the
in-process path — nor the `quaicu` command itself — may import them. This runs the quickstart in
a subprocess where those packages are made unimportable.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
OPTIONAL = (
    "fastapi", "starlette", "pydantic", "uvicorn", "jwt", "httpx",
    "asyncpg", "sqlalchemy", "alembic", "psycopg2", "mcp",
)

_SCRIPT = f"""
import importlib.abc, runpy, sys

class Block(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in {OPTIONAL!r}:
            raise ModuleNotFoundError(f"No module named {{name!r}} (blocked: not in the base install)")
        return None

sys.meta_path.insert(0, Block())
sys.path.insert(0, {str(REPO)!r})

import quaicu
from quaicu import Kernel, cli
from quaicu.adapters.identity.local_token import LocalTokenIdentityAdapter

assert cli.main(["version"]) == 0
namespace = runpy.run_path({str(REPO / "examples" / "quickstart.py")!r})
import asyncio
assert asyncio.run(namespace["main"]()) == 0
loaded = sorted(m for m in sys.modules if m.split(".")[0] in {OPTIONAL!r})
assert not loaded, loaded
print("base-install-ok")
"""


def test_in_process_use_and_the_cli_need_only_the_base_dependencies():
    result = subprocess.run(
        [sys.executable, "-c", _SCRIPT], check=False, capture_output=True, text=True, timeout=120
    )
    assert result.returncode == 0, result.stderr[-2000:]
    assert "base-install-ok" in result.stdout
