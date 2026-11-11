"""K·06 Process Engine — process definition DSL.

This module contains DATA only — no business logic, no I/O, no SDK imports.
The DSL types are K·06-internal; they extend ``ProcessDef`` (frozen, from
``core.types``) with the full step/transition graph needed to drive the state machine.

Architecture invariant (F-08): no import of temporalio, asyncpg, or any DB/SDK.
"""

from __future__ import annotations

from dataclasses import dataclass


# ── Step definition ───────────────────────────────────────────────────────────


@dataclass
class StepDef:
    """Definition of a single step in a governed process.

    All time-related fields are in seconds (or hours for ``hitl_timeout_hours``).
    Defaults are conservative — real definitions should set explicit values.
    """

    name: str
    timeout_seconds: int = 300
    max_retries: int = 3
    retry_backoff_base_seconds: float = 1.0
    compensation_step: str | None = None
    is_hitl: bool = False
    hitl_timeout_hours: int = 48
    sla_seconds: int | None = None


# ── Process definition ────────────────────────────────────────────────────────

# Terminal state sentinels — these appear as values in the transitions map
# and are recognised by the step runner as halting conditions.
TERMINAL_COMPLETED = "TERMINAL_COMPLETED"
TERMINAL_DENIED = "TERMINAL_DENIED"
TERMINAL_REJECTED = "TERMINAL_REJECTED"
TERMINAL_COMPENSATED = "TERMINAL_COMPENSATED"
TERMINAL_COMPENSATION_FAILED = "TERMINAL_COMPENSATION_FAILED"
DEAD_LETTER = "DEAD_LETTER"

TERMINAL_STATES: frozenset[str] = frozenset(
    {
        TERMINAL_COMPLETED,
        TERMINAL_DENIED,
        TERMINAL_REJECTED,
        TERMINAL_COMPENSATED,
        TERMINAL_COMPENSATION_FAILED,
        DEAD_LETTER,
    }
)


@dataclass
class GovernedProcessDef:
    """Full process definition for the governed action lifecycle.

    ``transitions`` maps ``step_name -> outcome -> next_step_or_terminal``.
    Terminal destinations are the ``TERMINAL_*`` / ``DEAD_LETTER`` sentinels above.
    """

    name: str
    version: int
    steps: list[StepDef]
    transitions: dict[str, dict[str, str]]

    # ── Helpers ───────────────────────────────────────────────────────────────

    def step_by_name(self, name: str) -> StepDef | None:
        """Return the StepDef with ``name``, or None if not found."""
        for step in self.steps:
            if step.name == name:
                return step
        return None

    def next_step(self, current_step: str, outcome: str) -> str:
        """Return the next step name (or terminal sentinel) for ``outcome`` from ``current_step``.

        Raises:
            KeyError: if ``current_step`` or ``outcome`` is not in the transitions map.
                The caller (state machine) must treat unknown transitions as HALT (F-03).
        """
        return self.transitions[current_step][outcome]

    def is_terminal(self, step_name: str) -> bool:
        """Return True if ``step_name`` is a terminal sentinel."""
        return step_name in TERMINAL_STATES


# ── Canonical process definition ──────────────────────────────────────────────

GOVERNED_ACTION_PROCESS = GovernedProcessDef(
    name="governed_action",
    version=1,
    steps=[
        StepDef(
            name="evaluate",
            timeout_seconds=30,
            max_retries=3,
            retry_backoff_base_seconds=1.0,
        ),
        StepDef(
            name="gate",
            timeout_seconds=48 * 3600,  # 48 h — enforced by hitl_timeout_hours
            max_retries=1,
            is_hitl=True,
            hitl_timeout_hours=48,
        ),
        StepDef(
            name="execute",
            timeout_seconds=300,
            max_retries=2,
            retry_backoff_base_seconds=1.0,
            compensation_step="compensate_execute",
        ),
        StepDef(
            name="seal",
            timeout_seconds=15,
            max_retries=5,
            retry_backoff_base_seconds=1.0,
        ),
        StepDef(
            name="emit",
            timeout_seconds=10,
            max_retries=3,
            retry_backoff_base_seconds=1.0,
        ),
        StepDef(
            name="compensate_execute",
            timeout_seconds=300,
            max_retries=2,
            retry_backoff_base_seconds=1.0,
        ),
    ],
    transitions={
        "evaluate": {
            "allow": "execute",
            "deny": TERMINAL_DENIED,
            "require_approval": "gate",
            "error": TERMINAL_DENIED,
        },
        "gate": {
            "approved": "execute",
            "rejected": TERMINAL_REJECTED,
            "timeout": TERMINAL_REJECTED,   # fail-closed (F-03)
            "cancelled": TERMINAL_REJECTED,
        },
        "execute": {
            "ok": "seal",
            "error": "compensate_execute",
        },
        "seal": {
            "ok": "emit",
            "error": DEAD_LETTER,
        },
        "emit": {
            "ok": TERMINAL_COMPLETED,
            "error": TERMINAL_COMPLETED,  # emit is non-fatal; outcome already sealed
        },
        "compensate_execute": {
            "ok": TERMINAL_COMPENSATED,
            "error": TERMINAL_COMPENSATION_FAILED,
        },
    },
)
