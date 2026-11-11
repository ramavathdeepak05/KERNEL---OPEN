"""The action state machine: legal transitions pass, illegal ones raise, terminals are dead-ends."""

from __future__ import annotations

import pytest

from quaicu.core.errors import LifecycleInvalidTransitionError
from quaicu.core.lifecycle.transitions import (
    VALID_TRANSITIONS,
    assert_transition,
    is_valid_transition,
)
from quaicu.core.types import TERMINAL_STATES, ActionState


def test_happy_path_transitions_are_legal() -> None:
    path = [
        ActionState.PROPOSED,
        ActionState.EVALUATING,
        ActionState.EXECUTING,
        ActionState.SEALING,
        ActionState.SEALED,
        ActionState.COMPLETED,
    ]
    for src, dst in zip(path, path[1:]):
        assert is_valid_transition(src, dst)
        assert_transition(src, dst)  # must not raise


def test_approval_path_is_legal() -> None:
    assert is_valid_transition(ActionState.EVALUATING, ActionState.PENDING_APPROVAL)
    assert is_valid_transition(ActionState.PENDING_APPROVAL, ActionState.EXECUTING)


@pytest.mark.parametrize(
    "src,dst",
    [
        (ActionState.PROPOSED, ActionState.EXECUTING),  # cannot skip evaluate (no-bypass)
        (ActionState.EVALUATING, ActionState.SEALED),  # cannot skip execute
        (ActionState.EXECUTING, ActionState.COMPLETED),  # cannot skip seal
        (ActionState.DENIED, ActionState.EXECUTING),  # terminal cannot resume
        (ActionState.COMPLETED, ActionState.EVALUATING),  # terminal is final
    ],
)
def test_illegal_transitions_raise(src: ActionState, dst: ActionState) -> None:
    assert not is_valid_transition(src, dst)
    with pytest.raises(LifecycleInvalidTransitionError):
        assert_transition(src, dst)


def test_terminal_states_have_no_outgoing_transitions() -> None:
    for state in TERMINAL_STATES:
        assert VALID_TRANSITIONS[state] == frozenset()
