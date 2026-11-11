"""Unit tests for K·06 saga / compensation sequence builder."""

from __future__ import annotations

from quaicu.core.process.definitions import GovernedProcessDef, StepDef
from quaicu.core.process.saga import build_compensation_sequence

_DEF = GovernedProcessDef(
    name="test",
    version=1,
    steps=[
        StepDef("evaluate"),
        StepDef("execute", compensation_step="compensate_execute"),
        StepDef("seal"),
        StepDef("compensate_execute"),
    ],
    transitions={
        "evaluate": {"allow": "execute"},
        "execute": {"ok": "seal", "error": "compensate_execute"},
        "seal": {"ok": "TERMINAL_COMPLETED"},
        "compensate_execute": {"ok": "TERMINAL_COMPENSATED"},
    },
)


def test_compensation_sequence_is_reversed():
    # failed_step="seal" (excluded); "execute" was completed before it and has a compensation
    completed = ["evaluate", "execute"]
    seq = build_compensation_sequence(_DEF, completed, "seal")
    # Only execute has a compensation step; evaluate does not
    assert seq == ["compensate_execute"]


def test_failed_step_excluded_from_compensation():
    completed = ["evaluate", "execute", "seal"]
    seq = build_compensation_sequence(_DEF, completed, "seal")
    # Only execute has a compensation_step; evaluate and seal do not
    assert seq == ["compensate_execute"]


def test_empty_completed_gives_empty_sequence():
    seq = build_compensation_sequence(_DEF, [], "execute")
    assert seq == []


def test_no_compensation_steps_declared():
    simple_def = GovernedProcessDef(
        name="simple",
        version=1,
        steps=[StepDef("a"), StepDef("b")],
        transitions={"a": {"ok": "b"}, "b": {"ok": "TERMINAL_COMPLETED"}},
    )
    seq = build_compensation_sequence(simple_def, ["a", "b"], "b")
    assert seq == []


def test_multiple_compensation_steps_in_order():
    multi_def = GovernedProcessDef(
        name="multi",
        version=1,
        steps=[
            StepDef("step1", compensation_step="comp1"),
            StepDef("step2", compensation_step="comp2"),
            StepDef("step3"),
        ],
        transitions={},
    )
    completed = ["step1", "step2", "step3"]
    seq = build_compensation_sequence(multi_def, completed, "step3")
    # Reversed order: step2 first, then step1
    assert seq == ["comp2", "comp1"]
