"""K·09 Fairness — domain models.

All values are immutable; computed from recorded decisions only (F-09).
The fairness sweep reads LedgerEntry records and produces FairnessMetrics
and FairnessDelta for the K·01 impact report.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class DecisionRecord:
    """Minimal projection from a LedgerEntry for fairness analysis.

    The sweep reads the ledger and projects only these fields — no model re-call.
    ``group_value`` is the value of the protected attribute (e.g. ``"high-risk-band"``)
    extracted from the recorded action payload.
    """

    action_id: str
    tenant_id: str
    decision: str  # "allow" | "deny" | "require_approval"
    group_value: str
    model_id: str | None = None
    recorded_at: datetime | None = None


@dataclass(frozen=True)
class FairnessMetrics:
    """Per-group deny rates computed over recorded decisions.

    ``group_rates`` maps each observed group value to its deny rate (0.0–1.0).
    ``total_decisions`` includes all records regardless of decision outcome.
    """

    tenant_id: str
    group_key: str
    group_rates: Mapping[str, float] = field(default_factory=dict)
    group_counts: Mapping[str, int] = field(default_factory=dict)
    total_decisions: int = 0
    model_id: str | None = None
    computed_at: datetime | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class FairnessDelta:
    """Difference in deny rates between active and candidate policy distributions.

    ``max_delta`` is the largest |active_rate − candidate_rate| across all groups.
    ``groups_above_threshold`` lists groups where the delta exceeds ``threshold``.
    The delta feeds the K·01 impact report that a reviewer must sign before
    a candidate policy moves to ACTIVATED (F-10).
    """

    tenant_id: str
    group_key: str
    active_rates: Mapping[str, float] = field(default_factory=dict)
    candidate_rates: Mapping[str, float] = field(default_factory=dict)
    max_delta: float = 0.0
    groups_above_threshold: tuple[str, ...] = ()
    threshold: float = 0.05
    computed_at: datetime | None = None
