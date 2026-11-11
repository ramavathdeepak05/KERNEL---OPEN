"""K·06 Process Engine — saga/compensation sequence builder.

Pure logic, no I/O. Given the completed forward steps and the failed step,
returns the compensation steps to run in reverse order.
"""

from __future__ import annotations

from quaicu.core.process.definitions import GovernedProcessDef


def build_compensation_sequence(
    definition: GovernedProcessDef,
    completed_steps: list[str],
    failed_step: str,
) -> list[str]:
    """Return compensation steps in reverse order for the completed forward steps.

    Only steps that declared a ``compensation_step`` are included.
    The failed step itself is excluded.
    """
    sequence: list[str] = []
    for step_name in reversed(completed_steps):
        if step_name == failed_step:
            continue
        step_def = definition.step_by_name(step_name)
        if step_def and step_def.compensation_step:
            sequence.append(step_def.compensation_step)
    return sequence
