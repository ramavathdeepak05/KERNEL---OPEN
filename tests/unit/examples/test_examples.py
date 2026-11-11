"""Every bundled example must run green — they are the first thing a new user executes."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_EXAMPLES = Path(__file__).resolve().parents[3] / "examples"


def _load(relative: str):
    path = _EXAMPLES / relative
    spec = importlib.util.spec_from_file_location(relative.replace("/", "_").replace("-", "_")[:-3], path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "script",
    [
        "quickstart.py",
        "sdk-approval-demo/demo.py",
        "underwriting-demo/demo.py",
        "policy-pack-demo/demo.py",
    ],
)
async def test_example_runs_to_completion(script: str):
    assert await _load(script).main() == 0
