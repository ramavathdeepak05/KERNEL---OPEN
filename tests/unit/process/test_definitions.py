"""Unit tests for K·06 process definitions (GovernedProcessDef, StepDef)."""

from __future__ import annotations

import pytest

from quaicu.core.process.definitions import (
    DEAD_LETTER,
    GOVERNED_ACTION_PROCESS,
    TERMINAL_COMPLETED,
    TERMINAL_DENIED,
    TERMINAL_REJECTED,
)


def test_governed_action_process_has_all_required_steps():
    step_names = {s.name for s in GOVERNED_ACTION_PROCESS.steps}
    assert "evaluate" in step_names
    assert "gate" in step_names
    assert "execute" in step_names
    assert "seal" in step_names
    assert "emit" in step_names


def test_gate_step_is_hitl():
    gate = GOVERNED_ACTION_PROCESS.step_by_name("gate")
    assert gate is not None
    assert gate.is_hitl is True


def test_hitl_timeout_routes_to_terminal_rejected():
    next_step = GOVERNED_ACTION_PROCESS.next_step("gate", "timeout")
    assert next_step == TERMINAL_REJECTED


def test_allow_skips_gate():
    next_step = GOVERNED_ACTION_PROCESS.next_step("evaluate", "allow")
    assert next_step == "execute"


def test_require_approval_routes_to_gate():
    next_step = GOVERNED_ACTION_PROCESS.next_step("evaluate", "require_approval")
    assert next_step == "gate"


def test_deny_is_terminal_denied():
    next_step = GOVERNED_ACTION_PROCESS.next_step("evaluate", "deny")
    assert next_step == TERMINAL_DENIED


def test_evaluate_error_is_fail_closed():
    next_step = GOVERNED_ACTION_PROCESS.next_step("evaluate", "error")
    assert next_step == TERMINAL_DENIED


def test_gate_approved_routes_to_execute():
    next_step = GOVERNED_ACTION_PROCESS.next_step("gate", "approved")
    assert next_step == "execute"


def test_gate_rejected_is_terminal():
    next_step = GOVERNED_ACTION_PROCESS.next_step("gate", "rejected")
    assert next_step == TERMINAL_REJECTED


def test_emit_error_still_completes():
    """Emit failure is non-fatal — action is already sealed."""
    next_step = GOVERNED_ACTION_PROCESS.next_step("emit", "error")
    assert next_step == TERMINAL_COMPLETED


def test_seal_error_goes_to_dead_letter():
    next_step = GOVERNED_ACTION_PROCESS.next_step("seal", "error")
    assert next_step == DEAD_LETTER


def test_step_by_name_returns_none_for_unknown():
    result = GOVERNED_ACTION_PROCESS.step_by_name("nonexistent")
    assert result is None


def test_next_step_raises_on_unknown_step():
    with pytest.raises(KeyError):
        GOVERNED_ACTION_PROCESS.next_step("nonexistent_step", "ok")


def test_next_step_raises_on_unknown_outcome():
    with pytest.raises(KeyError):
        GOVERNED_ACTION_PROCESS.next_step("evaluate", "unknown_outcome")


def test_is_terminal_recognizes_terminals():
    assert GOVERNED_ACTION_PROCESS.is_terminal(TERMINAL_COMPLETED)
    assert GOVERNED_ACTION_PROCESS.is_terminal(TERMINAL_DENIED)
    assert GOVERNED_ACTION_PROCESS.is_terminal(DEAD_LETTER)


def test_is_terminal_false_for_normal_step():
    assert not GOVERNED_ACTION_PROCESS.is_terminal("evaluate")
    assert not GOVERNED_ACTION_PROCESS.is_terminal("gate")
