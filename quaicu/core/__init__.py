"""QUAICU governance kernel — core.

ONE codebase · no forks · zero domain imports · fail-closed everywhere.

`core/` depends only on `core/` (its own ports, types, and errors). It never imports a concrete
adapter, a model SDK, a DB driver, or a queue. See AGENTS.md and the build spec §8.
"""

from __future__ import annotations

__version__ = "0.0.0"
