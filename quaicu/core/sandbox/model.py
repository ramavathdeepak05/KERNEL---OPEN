"""K·13 Sandbox — domain models.

Counterfactual replay: re-evaluates historical actions against candidate policies
using recorded model outputs (F-09). Writes only to a shadow partition — zero
production side effects. Powers the F-10 backtest gate in K·01.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal


@dataclass(frozen=True)
class SandboxDecision:
    """One counterfactual decision from the sandbox.

    ``flipped`` is True when the candidate decision differs from the recorded active decision.
    This is what feeds the F-10 impact report: the set of actions whose decision would change.
    """

    action_id: str
    tenant_id: str
    active_decision: str
    candidate_decision: str
    flipped: bool
    policy_version_used: str = ""
    recorded_outputs_used: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SandboxRun:
    """The aggregate result of a counterfactual replay run.

    ``flip_rate`` = decisions_flipped / ledger_entries_evaluated.
    ``fairness_delta`` is populated if a fairness sweep was also run (optional).

    A SandboxRun never touches the production ledger — all decisions go to
    an in-process shadow partition identified by ``run_id``.
    """

    run_id: str
    tenant_id: str
    policy_id: str
    policy_version: str
    run_type: Literal["backtest", "shadow"]
    ledger_entries_evaluated: int
    decisions_flipped: int
    decisions_unchanged: int
    flip_rate: float
    ran_at: datetime
    fairness_delta: float | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
