"""K· Lifecycle spine — the one sequence every governed action follows.

`propose → evaluate → gate → execute → seal → emit`. No step is optional, none can be skipped, and a
failure at any arrow → DENY (governance) or HALT (infra), never proceed (F-03, F-04).

Public surface:
- `LifecycleEngine` — the orchestrator.
- `VALID_TRANSITIONS`, `is_valid_transition`, `assert_transition` — the state machine.
- the collaborator protocols (`PolicyEvaluator`, `Ledger`, `EventBus`, `ActionRepository`) that K·01,
  K·02, K·07 and the storage adapter implement.
"""

from __future__ import annotations

from quaicu.core.lifecycle.engine import LifecycleEngine
from quaicu.core.lifecycle.protocols import ActionRepository, EventBus, Ledger, PolicyEvaluator
from quaicu.core.lifecycle.transitions import (
    VALID_TRANSITIONS,
    assert_transition,
    is_valid_transition,
)

__all__ = [
    "LifecycleEngine",
    "PolicyEvaluator",
    "Ledger",
    "EventBus",
    "ActionRepository",
    "VALID_TRANSITIONS",
    "is_valid_transition",
    "assert_transition",
]
