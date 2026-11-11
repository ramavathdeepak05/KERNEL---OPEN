"""The action state machine — the only legal `ActionState` transitions.

Any transition not in `VALID_TRANSITIONS` raises `LifecycleInvalidTransitionError`. This is the
authoritative encoding of the diagram in the `quaicu-governed-lifecycle` skill and build spec §10.
"""

from __future__ import annotations

from quaicu.core.errors import LifecycleInvalidTransitionError
from quaicu.core.types import ActionState

VALID_TRANSITIONS: dict[ActionState, frozenset[ActionState]] = {
    ActionState.PROPOSED: frozenset(
        {ActionState.EVALUATING, ActionState.CANCELLED, ActionState.DENIED}
    ),
    ActionState.EVALUATING: frozenset(
        {ActionState.EXECUTING, ActionState.PENDING_APPROVAL, ActionState.DENIED}
    ),
    ActionState.PENDING_APPROVAL: frozenset(
        {ActionState.EXECUTING, ActionState.DENIED, ActionState.HALTED}
    ),
    ActionState.EXECUTING: frozenset({ActionState.SEALING, ActionState.HALTED}),
    ActionState.SEALING: frozenset({ActionState.SEALED, ActionState.HALTED}),
    ActionState.SEALED: frozenset({ActionState.COMPLETED}),
    # terminal states — no outgoing transitions
    ActionState.COMPLETED: frozenset(),
    ActionState.DENIED: frozenset(),
    ActionState.HALTED: frozenset(),
    ActionState.CANCELLED: frozenset(),
}


def is_valid_transition(src: ActionState, dst: ActionState) -> bool:
    """True iff `src → dst` is a permitted transition."""
    return dst in VALID_TRANSITIONS.get(src, frozenset())


def assert_transition(src: ActionState, dst: ActionState) -> None:
    """Raise `LifecycleInvalidTransitionError` if `src → dst` is not permitted."""
    if not is_valid_transition(src, dst):
        raise LifecycleInvalidTransitionError(
            f"Illegal lifecycle transition {src.value} → {dst.value}",
            detail={"from": src.value, "to": dst.value},
        )
