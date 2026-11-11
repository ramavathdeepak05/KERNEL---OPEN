"""QUAICU Kernel — ASGI application entrypoint.

Loads a ``Kernel`` from the TOML config named by ``KERNEL_CONFIG`` (default: ``kernel.toml`` in the
current working directory) and builds the FastAPI app with ``create_app(kernel)``.

Usage::

    uvicorn quaicu.delivery.entrypoint:app --host 127.0.0.1 --port 7000

or, more simply, the ``quaicu serve`` command (``quaicu/cli.py``), which also supplies a local token
when none is configured.

Optional sections read here (the adapter sections are read by ``Kernel.from_config``)::

    [api]
    cors_origins = ["http://localhost:5173"]   # browser origins allowed to call the API

    [erasure]
    enabled = true                             # enable the right-to-erasure routes

    [anchor]
    interval_seconds = 300                     # periodic witness anchoring (needs a witness)
"""

from __future__ import annotations

import os
import tomllib

from quaicu.delivery.api.app import create_app
from quaicu.delivery.sdk.erasure_config import build_erasure
from quaicu.delivery.sdk.kernel import Kernel

_config_path = os.getenv("KERNEL_CONFIG", "kernel.toml")
kernel = Kernel.from_config(_config_path)

with open(_config_path, "rb") as _f:
    _config = tomllib.load(_f)

_api = _config.get("api", {}) or {}
_anchor = _config.get("anchor", {}) or {}

app = create_app(
    kernel,
    cors_origins=[str(o) for o in _api.get("cors_origins", [])] or None,
    erasure_engine=build_erasure(_config),
    anchor_interval=float(_anchor["interval_seconds"]) if _anchor.get("interval_seconds") else None,
)


def main() -> None:
    """Run the API with uvicorn. Prefer ``quaicu serve``; this is the bare entry point."""
    import uvicorn

    host = os.getenv("KERNEL_HOST", "127.0.0.1")
    port = int(os.getenv("KERNEL_PORT", "7000"))
    uvicorn.run("quaicu.delivery.entrypoint:app", host=host, port=port, workers=1)
